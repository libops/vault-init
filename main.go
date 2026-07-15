// Copyright 2018 Google Inc. All Rights Reserved.
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.

package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"

	"cloud.google.com/go/storage"
	"google.golang.org/api/cloudkms/v1"
	"google.golang.org/api/option"
)

var (
	vaultAddr     string
	gcsBucketName string
	httpClient    *http.Client

	vaultSecretShares      int
	vaultSecretThreshold   int
	vaultStoredShares      int
	vaultRecoveryShares    int
	vaultRecoveryThreshold int

	kmsService *cloudkms.Service
	kmsKeyId   string

	storageClient  *storage.Client
	metadataClient = newMetadataHTTPClient()

	version   = "devel"
	userAgent = fmt.Sprintf("vault-init/%s (%s)", version, runtime.Version())

	errShutdownBeforeInitialization = errors.New("shutdown requested before Vault initialization")
)

const (
	unsealKeysObjectName  = "unseal-keys.json.enc"
	rootTokenObjectName   = "root-token.enc" // #nosec G101 -- fixed GCS object name, not a credential value
	kmsPreflightPlaintext = "vault-init initialization preflight"
	secretWriteTimeout    = 2 * time.Minute
	maxSecretRetryDelay   = time.Minute
	maxEncryptedBundle    = 256 << 10
)

type secretEncrypter func(context.Context, []byte) ([]byte, error)
type secretDecrypter func(context.Context, []byte) ([]byte, error)
type encryptedSecretStore func(context.Context, string, []byte) error
type encryptedSecretStat func(context.Context, string) (int64, error)
type encryptedSecretReader func(context.Context, string) ([]byte, error)
type storagePermissionTester func(context.Context, []string) ([]string, error)
type storageRoundTripTester func(context.Context) error

// InitRequest holds a Vault init request.
type InitRequest struct {
	SecretShares      int `json:"secret_shares"`
	SecretThreshold   int `json:"secret_threshold"`
	StoredShares      int `json:"stored_shares"`
	RecoveryShares    int `json:"recovery_shares"`
	RecoveryThreshold int `json:"recovery_threshold"`
}

// InitResponse holds a Vault init response.
type InitResponse struct {
	Keys               []string `json:"keys"`
	KeysBase64         []string `json:"keys_base64"`
	RecoveryKeys       []string `json:"recovery_keys"`
	RecoveryKeysBase64 []string `json:"recovery_keys_base64"`
	RootToken          string   `json:"root_token"`
}

// UnsealRequest holds a Vault unseal request.
type UnsealRequest struct {
	Key   string `json:"key"`
	Reset bool   `json:"reset"`
}

// UnsealResponse holds a Vault unseal response.
type UnsealResponse struct {
	Sealed   bool `json:"sealed"`
	T        int  `json:"t"`
	N        int  `json:"n"`
	Progress int  `json:"progress"`
}

type metadataAccessTokenResponse struct {
	AccessToken string `json:"access_token"`
}

func main() {
	log.Println("Starting the vault-init service...")

	var err error

	vaultAddr = os.Getenv("VAULT_ADDR")
	if vaultAddr == "" {
		vaultAddr = "https://127.0.0.1:8200"
	}
	vaultAddr, err = validateVaultAddress(vaultAddr, boolFromEnv("VAULT_ALLOW_PLAINTEXT", false))
	if err != nil {
		log.Fatal(err)
	}

	vaultSecretShares = intFromEnv("VAULT_SECRET_SHARES", 5)
	vaultSecretThreshold = intFromEnv("VAULT_SECRET_THRESHOLD", 3)

	vaultInsecureSkipVerify := boolFromEnv("VAULT_SKIP_VERIFY", false)

	vaultAutoUnseal := boolFromEnv("VAULT_AUTO_UNSEAL", true)

	if vaultAutoUnseal {
		vaultStoredShares = intFromEnv("VAULT_STORED_SHARES", 1)
		vaultRecoveryShares = intFromEnv("VAULT_RECOVERY_SHARES", 1)
		vaultRecoveryThreshold = intFromEnv("VAULT_RECOVERY_THRESHOLD", 1)
	}

	vaultCaCert := stringFromEnv("VAULT_CACERT", "")
	vaultCaPath := stringFromEnv("VAULT_CAPATH", "")

	vaultClientTimeout := durFromEnv("VAULT_CLIENT_TIMEOUT", 60*time.Second)

	vaultServerName := stringFromEnv("VAULT_TLS_SERVER_NAME", "")

	checkInterval := durFromEnv("CHECK_INTERVAL", 10*time.Second)
	oneShot := checkInterval <= 0

	gcsBucketName = os.Getenv("GCS_BUCKET_NAME")
	if gcsBucketName == "" {
		log.Fatal("GCS_BUCKET_NAME must be set and not empty")
	}

	kmsKeyId = os.Getenv("KMS_KEY_ID")
	if kmsKeyId == "" {
		log.Fatal("KMS_KEY_ID must be set and not empty")
	}

	kmsCtx, kmsCtxCancel := context.WithCancel(context.Background())
	defer kmsCtxCancel()
	kmsService, err = cloudkms.NewService(kmsCtx)
	if err != nil {
		log.Fatal(err)
	}
	kmsService.UserAgent = userAgent

	storageCtx, storageCtxCancel := context.WithCancel(context.Background())
	defer storageCtxCancel()
	storageClient, err = storage.NewClient(storageCtx,
		option.WithUserAgent(userAgent),
		option.WithScopes(storage.ScopeReadWrite))
	if err != nil {
		log.Fatal(err)
	}

	tlsConfig := &tls.Config{
		InsecureSkipVerify: vaultInsecureSkipVerify, // #nosec G402 -- explicit, documented operator escape hatch
		MinVersion:         tls.VersionTLS12,
	}
	if err := processTLSConfig(tlsConfig, vaultServerName, vaultCaCert, vaultCaPath); err != nil {
		log.Fatal(err)
	}

	httpClient = &http.Client{
		Timeout:       vaultClientTimeout,
		CheckRedirect: refuseHTTPRedirect,
		Transport: &http.Transport{
			TLSClientConfig: tlsConfig,
		},
	}

	signalCh := make(chan os.Signal, 1)
	signal.Notify(signalCh, syscall.SIGINT, syscall.SIGTERM)

	stop := func(exitCode int) {
		log.Printf("Shutting down")
		kmsCtxCancel()
		storageCtxCancel()
		os.Exit(exitCode)
	}

	retryDelay := time.Second
	const maxRetryDelay = time.Minute
	retryAttempts := 0
	const maxRetryAttempts = 10

	for {
		select {
		case <-signalCh:
			stop(shutdownExitCode(oneShot))
		default:
		}
		request, err := newVaultRequest(http.MethodHead, vaultAddr+"/v1/sys/health", nil)
		if err != nil {
			log.Println(err)
			if oneShot {
				retryAttempts++
				if retryAttempts >= maxRetryAttempts {
					log.Printf("Health check failed after %d attempts; exiting with failure", retryAttempts)
					stop(1)
				}
				log.Printf(
					"Retrying health check in %s (exponential backoff), attempt %d/%d",
					retryDelay, retryAttempts, maxRetryAttempts,
				)
				time.Sleep(retryDelay)
				retryDelay *= 2
				if retryDelay > maxRetryDelay {
					retryDelay = maxRetryDelay
				}
				continue
			}
			time.Sleep(checkInterval)
			continue
		}

		response, err := httpClient.Do(request)

		if response != nil && response.Body != nil {
			_ = response.Body.Close()
		}

		if err != nil {
			log.Println(err)
			if oneShot {
				retryAttempts++
				if retryAttempts >= maxRetryAttempts {
					log.Printf("Health check failed after %d attempts; exiting with failure", retryAttempts)
					stop(1)
				}
				log.Printf(
					"Retrying health check in %s (exponential backoff), attempt %d/%d",
					retryDelay, retryAttempts, maxRetryAttempts,
				)
				time.Sleep(retryDelay)
				retryDelay *= 2
				if retryDelay > maxRetryDelay {
					retryDelay = maxRetryDelay
				}
				continue
			}
			time.Sleep(checkInterval)
			continue
		}

		retryDelay = time.Second
		retryAttempts = 0

		if healthStatusIndicatesInitialized(response.StatusCode) {
			if err := verifyDurableInitialization(); err != nil {
				log.Printf("Vault is initialized but its recovery material is not durable: %v", err)
				stop(1)
			}
		}

		switch response.StatusCode {
		case 200:
			log.Println("Vault is initialized and unsealed.")
		case 429:
			log.Println("Vault is unsealed and in standby mode.")
		case 472:
			log.Println("Vault is in disaster-recovery replication mode.")
		case 473:
			log.Println("Vault is a performance standby.")
		case 501:
			log.Println("Vault is not initialized.")
			log.Println("Initializing...")
			if err := initialize(signalCh); err != nil {
				log.Printf("Initialization failed: %v", err)
				if errors.Is(err, errShutdownBeforeInitialization) {
					stop(shutdownExitCode(oneShot))
				}
				if oneShot {
					stop(1)
				}
				break
			}
			if !vaultAutoUnseal {
				log.Println("Unsealing...")
				if err := unseal(); err != nil {
					log.Printf("Unseal failed: %v", err)
					if oneShot {
						stop(1)
					}
				}
			}
		case 503:
			log.Println("Vault is sealed.")
			if !vaultAutoUnseal {
				log.Println("Unsealing...")
				if err := unseal(); err != nil {
					log.Printf("Unseal failed: %v", err)
					if oneShot {
						stop(1)
					}
				}
			}
		default:
			log.Printf("Vault is in an unknown state. Status code: %d", response.StatusCode)
			if oneShot {
				stop(1)
			}
		}

		if oneShot {
			log.Printf("Check interval is non-positive, exiting.")
			stop(0)
		}

		log.Printf("Next check in %s", checkInterval)

		select {
		case <-signalCh:
			stop(shutdownExitCode(oneShot))
		case <-time.After(checkInterval):
		}
	}
}

func shutdownExitCode(oneShot bool) int {
	if oneShot {
		// A Cloud Run Job task terminated before it can finish must remain
		// retryable. Reporting success here could leave Vault uninitialized while
		// exhausting the job's retry policy.
		return 1
	}
	return 0
}

func healthStatusIndicatesInitialized(statusCode int) bool {
	switch statusCode {
	case 200, 429, 472, 473, 503:
		return true
	default:
		return false
	}
}

func initialize(shutdown <-chan os.Signal) error {
	initRequest := InitRequest{
		StoredShares:      vaultStoredShares,
		RecoveryShares:    vaultRecoveryShares,
		RecoveryThreshold: vaultRecoveryThreshold,
	}

	// allow optional secret shares/threshold to support GCP KMS on newer version of Vault
	if vaultSecretShares != 0 {
		initRequest.SecretShares = vaultSecretShares
	}
	if vaultSecretThreshold != 0 {
		initRequest.SecretThreshold = vaultSecretThreshold
	}

	initRequestData, err := json.Marshal(&initRequest)
	if err != nil {
		return fmt.Errorf("marshal initialization request: %w", err)
	}

	checkCtx, checkCancel := context.WithTimeout(context.Background(), secretWriteTimeout)
	err = preflightInitialization(
		checkCtx,
		statEncryptedSecret,
		testStoragePermissions,
		encryptSecretWithKMS,
		decryptSecretWithKMS,
		testStorageRoundTrip,
	)
	checkCancel()
	if err != nil {
		return err
	}
	if shutdownRequested(shutdown) {
		return errShutdownBeforeInitialization
	}

	r := bytes.NewReader(initRequestData)
	request, err := newVaultRequest(http.MethodPut, vaultAddr+"/v1/sys/init", r)
	if err != nil {
		return fmt.Errorf("create initialization request: %w", err)
	}
	if shutdownRequested(shutdown) {
		return errShutdownBeforeInitialization
	}

	response, err := httpClient.Do(request)
	if err != nil {
		return fmt.Errorf("initialize Vault: %w", err)
	}
	defer response.Body.Close()

	if response.StatusCode != http.StatusOK {
		return fmt.Errorf("init: non-200 status code: %d", response.StatusCode)
	}

	initRequestResponseBody, err := io.ReadAll(response.Body)
	if err != nil {
		if len(initRequestResponseBody) > 0 {
			persistenceErr := retryInitializationPersistence(
				initRequestResponseBody,
				"",
				encryptSecretWithKMS,
				storeEncryptedSecretOnce,
				time.Sleep,
			)
			return fmt.Errorf("read initialization response: %w (partial encrypted response preserved: %v)", err, persistenceErr)
		}
		return fmt.Errorf("read initialization response: %w", err)
	}

	var initResponse InitResponse

	if err := json.Unmarshal(initRequestResponseBody, &initResponse); err != nil {
		// Preserve every byte returned by the one-time endpoint even when its
		// shape is unexpected. Passing an empty root token makes the persistence
		// routine stop after the complete encrypted response is durable.
		persistenceErr := retryInitializationPersistence(
			initRequestResponseBody,
			"",
			encryptSecretWithKMS,
			storeEncryptedSecretOnce,
			time.Sleep,
		)
		return fmt.Errorf("decode initialization response: %w (%v)", err, persistenceErr)
	}

	// Vault returns its recovery material exactly once. Once the server accepts
	// the init request, do not honor shutdown or return to the health loop until
	// that material is durably encrypted and stored. Retrying in this process is
	// the only safe response to a transient KMS or GCS failure.
	log.Println("Encrypting and durably storing unseal keys and the root token...")
	if err := retryInitializationPersistence(
		initRequestResponseBody,
		initResponse.RootToken,
		encryptSecretWithKMS,
		storeEncryptedSecretOnce,
		time.Sleep,
	); err != nil {
		return err
	}

	log.Println("Initialization complete.")
	return nil
}

func shutdownRequested(shutdown <-chan os.Signal) bool {
	select {
	case <-shutdown:
		return true
	default:
		return false
	}
}

func preflightInitialization(
	ctx context.Context,
	stat encryptedSecretStat,
	testPermissions storagePermissionTester,
	encrypt secretEncrypter,
	decrypt secretDecrypter,
	storageRoundTrip storageRoundTripTester,
) error {
	if err := ensureInitializationTargetsEmpty(ctx, stat); err != nil {
		return err
	}
	requiredPermissions := []string{"storage.objects.create", "storage.objects.get"}
	grantedPermissions, err := testPermissions(ctx, requiredPermissions)
	if err != nil {
		return fmt.Errorf("verify GCS permissions before Vault initialization: %w", err)
	}
	granted := make(map[string]struct{}, len(grantedPermissions))
	for _, permission := range grantedPermissions {
		granted[permission] = struct{}{}
	}
	for _, permission := range requiredPermissions {
		if _, ok := granted[permission]; !ok {
			return fmt.Errorf("verify GCS permissions before Vault initialization: missing %s", permission)
		}
	}
	ciphertext, err := encrypt(ctx, []byte(kmsPreflightPlaintext))
	if err != nil {
		return fmt.Errorf("verify KMS encryption before Vault initialization: %w", err)
	}
	plaintext, err := decrypt(ctx, ciphertext)
	if err != nil {
		return fmt.Errorf("verify KMS decryption before Vault initialization: %w", err)
	}
	if !bytes.Equal(plaintext, []byte(kmsPreflightPlaintext)) {
		return fmt.Errorf("verify KMS before Vault initialization: round-trip plaintext mismatch")
	}
	if err := storageRoundTrip(ctx); err != nil {
		return fmt.Errorf("verify GCS create/read before Vault initialization: %w", err)
	}
	return nil
}

func testStoragePermissions(ctx context.Context, permissions []string) ([]string, error) {
	return storageClient.Bucket(gcsBucketName).IAM().TestPermissions(ctx, permissions)
}

func testStorageRoundTrip(ctx context.Context) error {
	marker := make([]byte, 32)
	if _, err := rand.Read(marker); err != nil {
		return fmt.Errorf("generate preflight marker: %w", err)
	}
	name := "vault-init-preflight/" + hex.EncodeToString(marker)
	return verifyStorageRoundTrip(ctx, name, marker, storeEncryptedSecretOnce, readEncryptedSecret)
}

func verifyStorageRoundTrip(
	ctx context.Context,
	name string,
	marker []byte,
	store encryptedSecretStore,
	read encryptedSecretReader,
) error {
	if len(marker) == 0 {
		return fmt.Errorf("preflight marker is empty")
	}
	if err := store(ctx, name, marker); err != nil {
		return fmt.Errorf("create marker object: %w", err)
	}
	stored, err := read(ctx, name)
	if err != nil {
		return fmt.Errorf("read marker object: %w", err)
	}
	if !bytes.Equal(stored, marker) {
		return fmt.Errorf("marker object content mismatch")
	}
	return nil
}

func retryInitializationPersistence(
	initResponse []byte,
	rootToken string,
	encrypt secretEncrypter,
	store encryptedSecretStore,
	wait func(time.Duration),
) error {
	retryDelay := time.Second

	// Protect and store the complete response before doing any work on the
	// redundant root-token object. This minimizes the interval in which a forced
	// task termination could destroy Vault's one-time recovery response.
	protectedResponse := retrySecretEncryption(
		initResponse,
		"initialization response",
		encrypt,
		wait,
		&retryDelay,
	)
	retrySecretStore(
		unsealKeysObjectName,
		protectedResponse,
		"initialization response",
		store,
		wait,
		&retryDelay,
	)
	log.Printf("Unseal keys written to gs://%s/%s", gcsBucketName, unsealKeysObjectName)

	if rootToken == "" {
		return fmt.Errorf("initialization response did not contain a root token; the complete encrypted response is durable at gs://%s/%s", gcsBucketName, unsealKeysObjectName)
	}

	protectedRootToken := retrySecretEncryption(
		[]byte(rootToken),
		"root token",
		encrypt,
		wait,
		&retryDelay,
	)
	retrySecretStore(
		rootTokenObjectName,
		protectedRootToken,
		"root token",
		store,
		wait,
		&retryDelay,
	)

	log.Printf("Root token written to gs://%s/%s", gcsBucketName, rootTokenObjectName)
	return nil
}

func retrySecretEncryption(
	plaintext []byte,
	description string,
	encrypt secretEncrypter,
	wait func(time.Duration),
	retryDelay *time.Duration,
) []byte {
	for {
		ctx, cancel := context.WithTimeout(context.Background(), secretWriteTimeout)
		ciphertext, err := encrypt(ctx, plaintext)
		cancel()
		if err == nil {
			return ciphertext
		}

		log.Printf("Protecting Vault %s failed; retaining it in memory and retrying in %s: %v", description, *retryDelay, err)
		wait(*retryDelay)
		*retryDelay = nextRetryDelay(*retryDelay)
	}
}

func retrySecretStore(
	name string,
	ciphertext []byte,
	description string,
	store encryptedSecretStore,
	wait func(time.Duration),
	retryDelay *time.Duration,
) {
	for {
		ctx, cancel := context.WithTimeout(context.Background(), secretWriteTimeout)
		err := store(ctx, name, ciphertext)
		cancel()
		if err == nil {
			return
		}

		log.Printf("Persisting Vault %s failed; retaining it in memory and retrying in %s: %v", description, *retryDelay, err)
		wait(*retryDelay)
		*retryDelay = nextRetryDelay(*retryDelay)
	}
}

func nextRetryDelay(current time.Duration) time.Duration {
	next := current * 2
	if next > maxSecretRetryDelay {
		return maxSecretRetryDelay
	}
	return next
}

func encryptSecretWithKMS(ctx context.Context, plaintext []byte) ([]byte, error) {
	request := &cloudkms.EncryptRequest{
		Plaintext: base64.StdEncoding.EncodeToString(plaintext),
	}
	response, err := kmsService.Projects.Locations.KeyRings.CryptoKeys.
		Encrypt(kmsKeyId, request).
		Context(ctx).
		Do()
	if err != nil {
		return nil, err
	}
	if response.Ciphertext == "" {
		return nil, fmt.Errorf("KMS returned empty ciphertext")
	}
	return []byte(response.Ciphertext), nil
}

func decryptSecretWithKMS(ctx context.Context, ciphertext []byte) ([]byte, error) {
	request := &cloudkms.DecryptRequest{Ciphertext: string(ciphertext)}
	response, err := kmsService.Projects.Locations.KeyRings.CryptoKeys.
		Decrypt(kmsKeyId, request).
		Context(ctx).
		Do()
	if err != nil {
		return nil, err
	}
	if response.Plaintext == "" {
		return nil, fmt.Errorf("KMS returned empty plaintext")
	}
	plaintext, err := base64.StdEncoding.DecodeString(response.Plaintext)
	if err != nil {
		return nil, fmt.Errorf("decode KMS plaintext: %w", err)
	}
	return plaintext, nil
}

func storeEncryptedSecretOnce(ctx context.Context, name string, ciphertext []byte) error {
	object := storageClient.Bucket(gcsBucketName).Object(name)
	writeCtx, cancelWrite := context.WithCancel(ctx)
	writer := object.If(storage.Conditions{DoesNotExist: true}).NewWriter(writeCtx)
	commitUncertain, err := writeObjectOnce(writer, cancelWrite, ciphertext)
	if err == nil {
		return nil
	}
	if !commitUncertain {
		return fmt.Errorf("write object: %w", err)
	}

	// A successful object commit can race with a lost Close response. Treat an
	// existing byte-identical object as success, while refusing to overwrite
	// recovery material from any other initialization.
	reader, readErr := object.NewReader(ctx)
	if readErr != nil {
		return fmt.Errorf("commit object: %w (verify existing object: %v)", err, readErr)
	}
	existing, readErr := io.ReadAll(io.LimitReader(reader, int64(len(ciphertext))+1))
	closeErr := reader.Close()
	if readErr != nil {
		return fmt.Errorf("commit object: %w (read existing object: %v)", err, readErr)
	}
	if closeErr != nil {
		return fmt.Errorf("commit object: %w (close existing object: %v)", err, closeErr)
	}
	if !bytes.Equal(existing, ciphertext) {
		return fmt.Errorf("commit object: %w (an object with different recovery material already exists)", err)
	}
	return nil
}

func writeObjectOnce(writer io.WriteCloser, cancel func(), data []byte) (commitUncertain bool, err error) {
	written, writeErr := writer.Write(data)
	if writeErr != nil || written != len(data) {
		if writeErr == nil {
			writeErr = io.ErrShortWrite
		}
		// Cancel before closing so Close cannot finalize a partial object.
		cancel()
		_ = writer.Close()
		return false, writeErr
	}
	closeErr := writer.Close()
	cancel()
	if closeErr != nil {
		// The server might have committed the object even though Close's response
		// was lost, so the caller must verify the create-only destination.
		return true, closeErr
	}
	return false, nil
}

func statEncryptedSecret(ctx context.Context, name string) (int64, error) {
	attrs, err := storageClient.Bucket(gcsBucketName).Object(name).Attrs(ctx)
	if err != nil {
		return 0, err
	}
	return attrs.Size, nil
}

func ensureInitializationTargetsEmpty(ctx context.Context, stat encryptedSecretStat) error {
	for _, name := range []string{unsealKeysObjectName, rootTokenObjectName} {
		_, err := stat(ctx, name)
		if errors.Is(err, storage.ErrObjectNotExist) {
			continue
		}
		if err != nil {
			return fmt.Errorf("check gs://%s/%s before Vault initialization: %w", gcsBucketName, name, err)
		}
		return fmt.Errorf("refusing to initialize Vault because gs://%s/%s already exists", gcsBucketName, name)
	}
	return nil
}

func verifyDurableInitialization() error {
	ctx, cancel := context.WithTimeout(context.Background(), secretWriteTimeout)
	defer cancel()

	initialErr := verifyStoredRecoveryMaterial(ctx, statEncryptedSecret)
	if initialErr == nil {
		return nil
	}

	bundleSize, bundleErr := statEncryptedSecret(ctx, unsealKeysObjectName)
	_, rootErr := statEncryptedSecret(ctx, rootTokenObjectName)
	if bundleErr != nil || bundleSize <= 0 || !errors.Is(rootErr, storage.ErrObjectNotExist) {
		return initialErr
	}

	if err := restoreRootTokenObject(
		ctx,
		readEncryptedSecret,
		decryptSecretWithKMS,
		encryptSecretWithKMS,
		storeEncryptedSecretOnce,
	); err != nil {
		return fmt.Errorf("%w; restore missing root-token object from durable response: %v", initialErr, err)
	}
	log.Printf("Restored root token to gs://%s/%s from the durable initialization response", gcsBucketName, rootTokenObjectName)
	return verifyStoredRecoveryMaterial(ctx, statEncryptedSecret)
}

func restoreRootTokenObject(
	ctx context.Context,
	read encryptedSecretReader,
	decrypt secretDecrypter,
	encrypt secretEncrypter,
	store encryptedSecretStore,
) error {
	protectedResponse, err := read(ctx, unsealKeysObjectName)
	if err != nil {
		return fmt.Errorf("read encrypted initialization response: %w", err)
	}
	initResponseJSON, err := decrypt(ctx, protectedResponse)
	if err != nil {
		return fmt.Errorf("decrypt initialization response: %w", err)
	}

	var initResponse InitResponse
	if err := json.Unmarshal(initResponseJSON, &initResponse); err != nil {
		return fmt.Errorf("decode initialization response: %w", err)
	}
	if initResponse.RootToken == "" {
		return fmt.Errorf("initialization response did not contain a root token")
	}

	protectedRootToken, err := encrypt(ctx, []byte(initResponse.RootToken))
	if err != nil {
		return fmt.Errorf("encrypt root token: %w", err)
	}
	if err := store(ctx, rootTokenObjectName, protectedRootToken); err != nil {
		return fmt.Errorf("store encrypted root token: %w", err)
	}
	return nil
}

func readEncryptedSecret(ctx context.Context, name string) ([]byte, error) {
	reader, err := storageClient.Bucket(gcsBucketName).Object(name).NewReader(ctx)
	if err != nil {
		return nil, err
	}
	data, readErr := io.ReadAll(io.LimitReader(reader, maxEncryptedBundle+1))
	closeErr := reader.Close()
	if readErr != nil {
		return nil, readErr
	}
	if closeErr != nil {
		return nil, closeErr
	}
	if len(data) == 0 {
		return nil, fmt.Errorf("encrypted object is empty")
	}
	if len(data) > maxEncryptedBundle {
		return nil, fmt.Errorf("encrypted object exceeds %d bytes", maxEncryptedBundle)
	}
	return data, nil
}

func verifyStoredRecoveryMaterial(ctx context.Context, stat encryptedSecretStat) error {
	for _, name := range []string{unsealKeysObjectName, rootTokenObjectName} {
		size, err := stat(ctx, name)
		if errors.Is(err, storage.ErrObjectNotExist) {
			return fmt.Errorf("gs://%s/%s is missing", gcsBucketName, name)
		}
		if err != nil {
			return fmt.Errorf("inspect gs://%s/%s: %w", gcsBucketName, name, err)
		}
		if size <= 0 {
			return fmt.Errorf("gs://%s/%s is empty", gcsBucketName, name)
		}
	}
	return nil
}

func unseal() error {
	ctx, cancel := context.WithTimeout(context.Background(), secretWriteTimeout)
	defer cancel()
	unsealKeysData, err := readEncryptedSecret(ctx, unsealKeysObjectName)
	if err != nil {
		return fmt.Errorf("read encrypted initialization response: %w", err)
	}

	unsealKeysPlaintext, err := decryptSecretWithKMS(ctx, unsealKeysData)
	if err != nil {
		return fmt.Errorf("decrypt initialization response: %w", err)
	}

	var initResponse InitResponse

	if err := json.Unmarshal(unsealKeysPlaintext, &initResponse); err != nil {
		return fmt.Errorf("decode initialization response: %w", err)
	}
	if len(initResponse.KeysBase64) == 0 {
		return fmt.Errorf("initialization response contains no unseal keys")
	}

	for _, key := range initResponse.KeysBase64 {
		done, err := unsealOne(key)
		if err != nil {
			return err
		}
		if done {
			return nil
		}
	}

	return fmt.Errorf("vault remains sealed after submitting %d unseal keys", len(initResponse.KeysBase64))
}

func unsealOne(key string) (bool, error) {
	unsealRequest := UnsealRequest{
		Key: key,
	}

	unsealRequestData, err := json.Marshal(&unsealRequest)
	if err != nil {
		return false, err
	}

	r := bytes.NewReader(unsealRequestData)
	request, err := newVaultRequest(http.MethodPut, vaultAddr+"/v1/sys/unseal", r)
	if err != nil {
		return false, err
	}

	response, err := httpClient.Do(request)
	if err != nil {
		return false, err
	}
	defer response.Body.Close()

	if response.StatusCode != 200 {
		return false, fmt.Errorf("unseal: non-200 status code: %d", response.StatusCode)
	}

	unsealRequestResponseBody, err := io.ReadAll(response.Body)
	if err != nil {
		return false, err
	}

	var unsealResponse UnsealResponse
	if err := json.Unmarshal(unsealRequestResponseBody, &unsealResponse); err != nil {
		return false, err
	}

	if !unsealResponse.Sealed {
		return true, nil
	}

	return false, nil
}

func processTLSConfig(cfg *tls.Config, serverName, caCert, caPath string) error {
	cfg.ServerName = serverName

	// If a CA cert is provided, trust only that cert
	if caCert != "" {
		b, err := os.ReadFile(caCert) // #nosec G304 -- explicit operator-supplied CA file
		if err != nil {
			return fmt.Errorf("failed to read CA cert: %w", err)
		}

		root := x509.NewCertPool()
		if ok := root.AppendCertsFromPEM(b); !ok {
			return fmt.Errorf("failed to parse CA cert")
		}

		cfg.RootCAs = root
		return nil
	}

	// If a directory is provided, trust only the certs in that directory
	if caPath != "" {
		files, err := os.ReadDir(caPath)
		if err != nil {
			return fmt.Errorf("failed to read CA path: %w", err)
		}

		root := x509.NewCertPool()

		for _, f := range files {
			if f.IsDir() {
				continue
			}
			b, err := os.ReadFile(filepath.Join(caPath, f.Name())) // #nosec G304 -- name came from ReadDir of this directory
			if err != nil {
				return fmt.Errorf("failed to read cert: %w", err)
			}
			if ok := root.AppendCertsFromPEM(b); !ok {
				return fmt.Errorf("failed to parse cert")
			}
		}

		cfg.RootCAs = root
		return nil
	}

	return nil
}

func newVaultRequest(method, url string, body io.Reader) (*http.Request, error) {
	request, err := http.NewRequest(method, url, body)
	if err != nil {
		return nil, err
	}

	request.Header.Set("Accept", "application/json")
	if method == http.MethodPut {
		request.Header.Set("Content-Type", "application/json")
	}

	// The proxy deliberately exposes the health endpoint without credentials.
	// Avoid minting and transmitting a privileged Google token for the frequent
	// readiness poll; only initialization and unseal operations require it.
	if request.URL.Path == "/v1/sys/health" {
		return request, nil
	}

	accessToken, err := accessTokenFromMetadata()
	if err != nil {
		return nil, fmt.Errorf("failed to get access token from metadata server: %w", err)
	}

	request.Header.Set("X-Admin-Token", accessToken)

	return request, nil
}

func refuseHTTPRedirect(_ *http.Request, _ []*http.Request) error {
	// Never let a redirect move a privileged Vault header to another URL, turn an
	// initialization PUT into a GET with ambiguous commit semantics, or move the
	// metadata token exchange away from the link-local metadata service.
	return http.ErrUseLastResponse
}

func validateVaultAddress(raw string, allowPlaintext bool) (string, error) {
	address, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return "", fmt.Errorf("parse VAULT_ADDR: %w", err)
	}
	if address.Scheme == "" || address.Host == "" || address.Opaque != "" {
		return "", fmt.Errorf("VAULT_ADDR must be an absolute URL")
	}
	if address.User != nil {
		return "", fmt.Errorf("VAULT_ADDR must not contain credentials")
	}
	if address.RawQuery != "" || address.Fragment != "" {
		return "", fmt.Errorf("VAULT_ADDR must not contain a query or fragment")
	}
	if address.Path != "" && address.Path != "/" {
		return "", fmt.Errorf("VAULT_ADDR must not contain a path")
	}

	address.Scheme = strings.ToLower(address.Scheme)
	switch address.Scheme {
	case "https":
	case "http":
		if !allowPlaintext {
			return "", fmt.Errorf("VAULT_ADDR uses plaintext HTTP; set VAULT_ALLOW_PLAINTEXT=true only for an explicitly accepted development risk")
		}
	default:
		return "", fmt.Errorf("VAULT_ADDR must use HTTPS")
	}

	address.Path = ""
	address.RawPath = ""
	return address.String(), nil
}

func accessTokenFromMetadata() (string, error) {
	const metadataTokenURL = "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token" // #nosec G101 -- metadata endpoint, not a credential value

	request, err := http.NewRequest(http.MethodGet, metadataTokenURL, nil)
	if err != nil {
		return "", err
	}
	request.Header.Set("Metadata-Flavor", "Google")

	response, err := metadataClient.Do(request)
	if err != nil {
		return "", err
	}
	defer response.Body.Close()

	if response.StatusCode != http.StatusOK {
		return "", fmt.Errorf("unexpected status code: %d", response.StatusCode)
	}

	var tokenResponse metadataAccessTokenResponse
	if err := json.NewDecoder(response.Body).Decode(&tokenResponse); err != nil {
		return "", err
	}

	if tokenResponse.AccessToken == "" {
		return "", fmt.Errorf("metadata server returned empty access token")
	}

	return tokenResponse.AccessToken, nil
}

func newMetadataHTTPClient() *http.Client {
	return &http.Client{
		Timeout:       5 * time.Second,
		CheckRedirect: refuseHTTPRedirect,
		// The metadata endpoint is necessarily plain HTTP. A nil Proxy function
		// deliberately prevents HTTP_PROXY from observing its token response.
		Transport: &http.Transport{
			Proxy:             nil,
			DisableKeepAlives: true,
		},
	}
}

func boolFromEnv(env string, def bool) bool {
	val := os.Getenv(env)
	if val == "" {
		return def
	}
	b, err := strconv.ParseBool(val)
	if err != nil {
		log.Fatalf("failed to parse %q: %s", env, err)
	}
	return b
}

func intFromEnv(env string, def int) int {
	val := os.Getenv(env)
	if val == "" {
		return def
	}
	i, err := strconv.Atoi(val)
	if err != nil {
		log.Fatalf("failed to parse %q: %s", env, err)
	}
	return i
}

func stringFromEnv(env string, def string) string {
	val := os.Getenv(env)
	if val == "" {
		return def
	}
	return val
}

func durFromEnv(env string, def time.Duration) time.Duration {
	val := os.Getenv(env)
	if val == "" {
		return def
	}
	r := val[len(val)-1]
	if r >= '0' && r <= '9' {
		val = val + "s" // assume seconds
	}
	d, err := time.ParseDuration(val)
	if err != nil {
		log.Fatalf("failed to parse %q: %s", env, err)
	}
	return d
}
