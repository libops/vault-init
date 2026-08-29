// Copyright 2018 Google Inc. All Rights Reserved.
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.

package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
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
	vaultRecoveryPGPKeys   []string

	kmsService *cloudkms.Service
	kmsKeyId   string

	storageClient  *storage.Client
	metadataClient = newMetadataHTTPClient()

	version   = "devel"
	userAgent = fmt.Sprintf("vault-init/%s (%s)", version, runtime.Version())

	errShutdownBeforeInitialization = errors.New("shutdown requested before Vault initialization")
)

const (
	unsealKeysObjectName        = "unseal-keys.json.enc"
	rootTokenObjectName         = "root-token.enc" // #nosec G101 -- legacy fixed object name, not a credential value
	bootstrapCompleteObjectName = "bootstrap-complete.json"
	kmsPreflightPlaintext       = "vault-init initialization preflight"
	metadataTokenURL            = "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token" // #nosec G101 -- metadata endpoint, not a credential value
	vaultProxyEmailScope        = "https://www.googleapis.com/auth/userinfo.email"
	secretWriteTimeout          = 2 * time.Minute
	maxSecretRetryDelay         = time.Minute
	maxEncryptedBundle          = 256 << 10
	maxAuditAttempts            = 5
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
	SecretShares      int      `json:"secret_shares"`
	SecretThreshold   int      `json:"secret_threshold"`
	StoredShares      int      `json:"stored_shares"`
	RecoveryShares    int      `json:"recovery_shares"`
	RecoveryThreshold int      `json:"recovery_threshold"`
	RecoveryPGPKeys   []string `json:"recovery_pgp_keys,omitempty"`
}

// InitResponse holds a Vault init response.
type InitResponse struct {
	Keys               []string `json:"keys"`
	KeysBase64         []string `json:"keys_base64"`
	RecoveryKeys       []string `json:"recovery_keys"`
	RecoveryKeysBase64 []string `json:"recovery_keys_base64"`
	RootToken          string   `json:"root_token"`
}

type bootstrapCompletion struct {
	SchemaVersion      int      `json:"schema_version"`
	AuditPath          string   `json:"audit_path"`
	RootTokenRevoked   bool     `json:"root_token_revoked"`
	RecoveryShares     int      `json:"recovery_shares"`
	RecoveryThreshold  int      `json:"recovery_threshold"`
	CustodianKeySHA256 []string `json:"custodian_key_sha256"`
}

type auditDevice struct {
	Type    string            `json:"type"`
	Options map[string]string `json:"options"`
}

type rootGenerationStatus struct {
	Started      bool   `json:"started"`
	Nonce        string `json:"nonce"`
	Progress     int    `json:"progress"`
	Required     int    `json:"required"`
	EncodedToken string `json:"encoded_token"`
	OTP          string `json:"otp"`
	OTPLength    int    `json:"otp_length"`
	Complete     bool   `json:"complete"`
}

type tokenData struct {
	Accessor string   `json:"accessor"`
	Policies []string `json:"policies"`
}

type tokenLookupResponse struct {
	Data tokenData `json:"data"`
}

type tokenAccessorListResponse struct {
	Data struct {
		Keys []string `json:"keys"`
	} `json:"data"`
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
		vaultRecoveryShares = intFromEnv("VAULT_RECOVERY_SHARES", 5)
		vaultRecoveryThreshold = intFromEnv("VAULT_RECOVERY_THRESHOLD", 3)
		if strings.TrimSpace(os.Getenv("VAULT_RECOVERY_PGP_KEYS")) != "" {
			vaultRecoveryPGPKeys, err = recoveryPGPKeysFromEnv("VAULT_RECOVERY_PGP_KEYS", vaultRecoveryShares, vaultRecoveryThreshold)
			if err != nil {
				log.Fatal(err)
			}
		}
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
		RecoveryPGPKeys:   vaultRecoveryPGPKeys,
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
		return fmt.Errorf("read initialization response: %w; refusing to persist an unvalidated response that may contain a live root token", err)
	}

	var initResponse InitResponse

	if err := json.Unmarshal(initRequestResponseBody, &initResponse); err != nil {
		return fmt.Errorf("decode initialization response: %w; refusing to persist an unvalidated response that may contain a live root token", err)
	}
	if initResponse.RootToken == "" {
		return fmt.Errorf("initialization response did not contain a root token")
	}
	if len(initResponse.RecoveryKeys) == 0 && len(initResponse.RecoveryKeysBase64) == 0 &&
		len(initResponse.Keys) == 0 && len(initResponse.KeysBase64) == 0 {
		return fmt.Errorf("initialization response did not contain recovery or unseal keys")
	}

	// Vault returns its recovery material exactly once. Once the server accepts
	// the init request, first persist a root-token-free recovery bundle. Enable
	// the audit device next so revocation itself is audited, revoke and verify the
	// initial root token, and only then publish the non-secret completion marker.
	// A crash after the recovery bundle is durable but before completion fails
	// closed for a quorum-based operator repair; it never leaves a root token in
	// GCS for an automated retry.
	log.Println("Encrypting and durably storing root-token-free recovery material...")
	if err := retryRecoveryPersistence(
		initResponse,
		encryptSecretWithKMS,
		storeEncryptedSecretOnce,
		time.Sleep,
	); err != nil {
		return err
	}
	if err := enableAuditAndRevokeInitialRoot(initResponse.RootToken); err != nil {
		return fmt.Errorf("secure bootstrap incomplete after recovery material became durable: %w; use the recovery-key quorum to inspect audit state and generate a short-lived repair token", err)
	}
	if err := persistBootstrapCompletion(storeEncryptedSecretOnce, time.Sleep); err != nil {
		return err
	}

	log.Println("Initialization complete; audit is enabled and the initial root token is revoked.")
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

func retryRecoveryPersistence(
	initResponse InitResponse,
	encrypt secretEncrypter,
	store encryptedSecretStore,
	wait func(time.Duration),
) error {
	retryDelay := time.Second

	// Never serialize the initial root token into the recovery object. Recovery
	// keys are the durable break-glass mechanism and can generate a short-lived
	// root token with the configured quorum when an operator explicitly needs it.
	initResponse.RootToken = ""
	recoveryResponse, err := json.Marshal(initResponse)
	if err != nil {
		return fmt.Errorf("marshal root-token-free recovery response: %w", err)
	}
	protectedResponse := retrySecretEncryption(
		recoveryResponse,
		"recovery response",
		encrypt,
		wait,
		&retryDelay,
	)
	retrySecretStore(
		unsealKeysObjectName,
		protectedResponse,
		"recovery response",
		store,
		wait,
		&retryDelay,
	)
	log.Printf("Root-token-free recovery material written to gs://%s/%s", gcsBucketName, unsealKeysObjectName)
	return nil
}

func persistBootstrapCompletion(store encryptedSecretStore, wait func(time.Duration)) error {
	custodianDigests, err := recoveryPGPKeyDigests(vaultRecoveryPGPKeys)
	if err != nil {
		return fmt.Errorf("derive recovery custodian fingerprints: %w", err)
	}
	record, err := json.Marshal(bootstrapCompletion{
		SchemaVersion:      1,
		AuditPath:          "cloudrun",
		RootTokenRevoked:   true,
		RecoveryShares:     vaultRecoveryShares,
		RecoveryThreshold:  vaultRecoveryThreshold,
		CustodianKeySHA256: custodianDigests,
	})
	if err != nil {
		return fmt.Errorf("marshal bootstrap completion: %w", err)
	}
	retryDelay := time.Second
	retrySecretStore(
		bootstrapCompleteObjectName,
		record,
		"non-secret bootstrap completion",
		store,
		wait,
		&retryDelay,
	)
	log.Printf("Secure bootstrap completion written to gs://%s/%s", gcsBucketName, bootstrapCompleteObjectName)
	return nil
}

func enableAuditAndRevokeInitialRoot(rootToken string) error {
	return enableAuditAndRevokeInitialRootWithWait(rootToken, time.Sleep)
}

func enableAuditAndRevokeInitialRootWithWait(rootToken string, wait func(time.Duration)) error {
	if rootToken == "" {
		return fmt.Errorf("initial root token is empty")
	}
	if err := retryEnsureStdoutAuditDevice(rootToken, wait); err != nil {
		return err
	}
	if err := revokeInitialRootToken(rootToken); err != nil {
		return err
	}
	return verifyInitialRootTokenRevoked(rootToken)
}

func retryEnsureStdoutAuditDevice(rootToken string, wait func(time.Duration)) error {
	retryDelay := time.Second
	var err error
	for attempt := 1; attempt <= maxAuditAttempts; attempt++ {
		if err = ensureStdoutAuditDevice(rootToken); err == nil {
			return nil
		}
		if attempt == maxAuditAttempts {
			break
		}
		log.Printf("Establishing the Vault stdout audit device failed; retrying in %s (attempt %d/%d): %v", retryDelay, attempt, maxAuditAttempts, err)
		wait(retryDelay)
		retryDelay = nextRetryDelay(retryDelay)
	}
	return fmt.Errorf("establish stdout audit device after %d attempts: %w", maxAuditAttempts, err)
}

func ensureStdoutAuditDevice(rootToken string) error {
	devices, err := readAuditDevices(rootToken)
	if err != nil {
		return fmt.Errorf("read audit devices: %w", err)
	}
	if device, ok := devices["cloudrun/"]; ok {
		return validateStdoutAuditDevice(device)
	}

	payload, err := json.Marshal(map[string]any{
		"type":        "file",
		"description": "Cloud Run stdout audit stream",
		"options": map[string]string{
			"file_path":            "stdout",
			"format":               "json",
			"hmac_accessor":        "true",
			"log_raw":              "false",
			"elide_list_responses": "true",
		},
	})
	if err != nil {
		return fmt.Errorf("marshal audit configuration: %w", err)
	}
	status, _, err := doRootVaultRequest(http.MethodPost, "/v1/sys/audit/cloudrun", payload, rootToken)
	if err != nil {
		return fmt.Errorf("enable stdout audit device: %w", err)
	}
	if status != http.StatusNoContent {
		return fmt.Errorf("enable stdout audit device: unexpected status %d", status)
	}
	devices, err = readAuditDevices(rootToken)
	if err != nil {
		return fmt.Errorf("verify stdout audit device: %w", err)
	}
	device, ok := devices["cloudrun/"]
	if !ok {
		return fmt.Errorf("verify stdout audit device: cloudrun/ is absent")
	}
	return validateStdoutAuditDevice(device)
}

func readAuditDevices(rootToken string) (map[string]auditDevice, error) {
	status, body, err := doRootVaultRequest(http.MethodGet, "/v1/sys/audit", nil, rootToken)
	if err != nil {
		return nil, err
	}
	if status != http.StatusOK {
		return nil, fmt.Errorf("unexpected status %d", status)
	}
	var devices map[string]auditDevice
	if err := json.Unmarshal(body, &devices); err != nil {
		return nil, fmt.Errorf("decode audit devices: %w", err)
	}
	return devices, nil
}

func validateStdoutAuditDevice(device auditDevice) error {
	if device.Type != "file" || device.Options["file_path"] != "stdout" ||
		device.Options["log_raw"] == "true" {
		return fmt.Errorf("cloudrun/ audit device must be file output to stdout with raw secret logging disabled")
	}
	return nil
}

func revokeInitialRootToken(rootToken string) error {
	status, _, err := doRootVaultRequest(http.MethodPost, "/v1/auth/token/revoke-self", nil, rootToken)
	if err != nil {
		return fmt.Errorf("revoke initial root token: %w", err)
	}
	if status != http.StatusNoContent {
		return fmt.Errorf("revoke initial root token: unexpected status %d", status)
	}
	return nil
}

func verifyInitialRootTokenRevoked(rootToken string) error {
	status, _, err := doRootVaultRequest(http.MethodGet, "/v1/auth/token/lookup-self", nil, rootToken)
	if err != nil {
		return fmt.Errorf("verify initial root token revocation: %w", err)
	}
	if status != http.StatusForbidden {
		return fmt.Errorf("verify initial root token revocation: got status %d, want 403", status)
	}
	return nil
}

func doRootVaultRequest(method, requestPath string, payload []byte, rootToken string) (int, []byte, error) {
	var body io.Reader
	if payload != nil {
		body = bytes.NewReader(payload)
	}
	request, err := newVaultRequest(method, vaultAddr+requestPath, body)
	if err != nil {
		return 0, nil, err
	}
	request.Header.Set("X-Vault-Token", rootToken)
	if payload != nil {
		request.Header.Set("Content-Type", "application/json")
	}
	response, err := httpClient.Do(request)
	if err != nil {
		return 0, nil, err
	}
	defer response.Body.Close()
	responseBody, err := io.ReadAll(io.LimitReader(response.Body, maxEncryptedBundle+1))
	if err != nil {
		return 0, nil, err
	}
	if len(responseBody) > maxEncryptedBundle {
		return 0, nil, fmt.Errorf("vault response exceeds %d bytes", maxEncryptedBundle)
	}
	return response.StatusCode, responseBody, nil
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
	for _, name := range []string{unsealKeysObjectName, bootstrapCompleteObjectName, rootTokenObjectName} {
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
	completionSize, err := statEncryptedSecret(ctx, bootstrapCompleteObjectName)
	if errors.Is(err, storage.ErrObjectNotExist) {
		recovery, loadErr := loadIncompleteBootstrapRecovery(
			ctx,
			statEncryptedSecret,
			readEncryptedSecret,
			decryptSecretWithKMS,
		)
		if loadErr != nil {
			return loadErr
		}
		return resumeIncompleteBootstrap(recovery, storeEncryptedSecretOnce, time.Sleep)
	}
	if err != nil {
		return fmt.Errorf("inspect gs://%s/%s: %w", gcsBucketName, bootstrapCompleteObjectName, err)
	}
	if completionSize <= 0 {
		return fmt.Errorf("gs://%s/%s is empty", gcsBucketName, bootstrapCompleteObjectName)
	}
	if err := verifyStoredRecoveryMaterial(ctx, statEncryptedSecret); err != nil {
		return err
	}
	if err := verifyRecoveryBundleContents(ctx, readEncryptedSecret, decryptSecretWithKMS); err != nil {
		return err
	}
	return verifyBootstrapCompletion(ctx, readEncryptedSecret)
}

func loadIncompleteBootstrapRecovery(
	ctx context.Context,
	stat encryptedSecretStat,
	read encryptedSecretReader,
	decrypt secretDecrypter,
) (InitResponse, error) {
	size, err := stat(ctx, unsealKeysObjectName)
	if errors.Is(err, storage.ErrObjectNotExist) {
		return InitResponse{}, fmt.Errorf("gs://%s/%s is missing", gcsBucketName, unsealKeysObjectName)
	}
	if err != nil {
		return InitResponse{}, fmt.Errorf("inspect gs://%s/%s: %w", gcsBucketName, unsealKeysObjectName, err)
	}
	if size <= 0 {
		return InitResponse{}, fmt.Errorf("gs://%s/%s is empty", gcsBucketName, unsealKeysObjectName)
	}

	if size, err = stat(ctx, rootTokenObjectName); err == nil {
		return InitResponse{}, fmt.Errorf("legacy gs://%s/%s still exists (%d bytes); refusing automatic bootstrap recovery", gcsBucketName, rootTokenObjectName, size)
	} else if !errors.Is(err, storage.ErrObjectNotExist) {
		return InitResponse{}, fmt.Errorf("inspect legacy gs://%s/%s: %w", gcsBucketName, rootTokenObjectName, err)
	}

	if _, err = stat(ctx, bootstrapCompleteObjectName); err == nil {
		return InitResponse{}, fmt.Errorf("gs://%s/%s already exists; refusing incomplete-bootstrap recovery", gcsBucketName, bootstrapCompleteObjectName)
	} else if !errors.Is(err, storage.ErrObjectNotExist) {
		return InitResponse{}, fmt.Errorf("inspect gs://%s/%s: %w", gcsBucketName, bootstrapCompleteObjectName, err)
	}

	return readRecoveryBundleContents(ctx, read, decrypt)
}

func verifyRecoveryBundleContents(ctx context.Context, read encryptedSecretReader, decrypt secretDecrypter) error {
	_, err := readRecoveryBundleContents(ctx, read, decrypt)
	return err
}

func readRecoveryBundleContents(ctx context.Context, read encryptedSecretReader, decrypt secretDecrypter) (InitResponse, error) {
	protectedResponse, err := read(ctx, unsealKeysObjectName)
	if err != nil {
		return InitResponse{}, fmt.Errorf("read encrypted recovery response: %w", err)
	}
	recoveryJSON, err := decrypt(ctx, protectedResponse)
	if err != nil {
		return InitResponse{}, fmt.Errorf("decrypt recovery response: %w", err)
	}
	var recovery InitResponse
	if err := json.Unmarshal(recoveryJSON, &recovery); err != nil {
		return InitResponse{}, fmt.Errorf("decode recovery response: %w", err)
	}
	if recovery.RootToken != "" {
		return InitResponse{}, fmt.Errorf("encrypted recovery response retains an initial root token; migrate it to the root-token-free schema under dual control")
	}
	if len(recovery.RecoveryKeys) == 0 && len(recovery.RecoveryKeysBase64) == 0 &&
		len(recovery.Keys) == 0 && len(recovery.KeysBase64) == 0 {
		return InitResponse{}, fmt.Errorf("encrypted recovery response contains no recovery or unseal keys")
	}
	return recovery, nil
}

func resumeIncompleteBootstrap(recovery InitResponse, store encryptedSecretStore, wait func(time.Duration)) (err error) {
	if len(vaultRecoveryPGPKeys) != 0 {
		return fmt.Errorf("automatic bootstrap recovery is unavailable when recovery shares use PGP custodian custody")
	}
	repairToken, err := generateRecoveryRootToken(recovery)
	if err != nil {
		return fmt.Errorf("generate temporary recovery root token: %w", err)
	}
	repairTokenLive := true
	defer func() {
		if !repairTokenLive {
			return
		}
		if revokeErr := revokeInitialRootToken(repairToken); revokeErr != nil {
			err = errors.Join(err, fmt.Errorf("revoke temporary recovery root token after recovery failure: %w", revokeErr))
		}
	}()

	if err = retryEnsureStdoutAuditDevice(repairToken, wait); err != nil {
		return err
	}
	if err = revokeOtherRootTokens(repairToken); err != nil {
		return err
	}
	if err = revokeInitialRootToken(repairToken); err != nil {
		return fmt.Errorf("revoke temporary recovery root token: %w", err)
	}
	if err = verifyInitialRootTokenRevoked(repairToken); err != nil {
		return fmt.Errorf("verify temporary recovery root token revocation: %w", err)
	}
	repairTokenLive = false

	if err = persistBootstrapCompletion(store, wait); err != nil {
		return err
	}
	log.Println("Recovered incomplete secure bootstrap; audit is enabled and all root-policy tokens are revoked.")
	return nil
}

func generateRecoveryRootToken(recovery InitResponse) (string, error) {
	shares := recovery.RecoveryKeysBase64
	if len(shares) == 0 {
		shares = recovery.RecoveryKeys
	}
	if len(shares) == 0 {
		return "", fmt.Errorf("KMS recovery bundle contains no Vault recovery keys")
	}
	if vaultRecoveryThreshold < 2 || vaultRecoveryThreshold > len(shares) {
		return "", fmt.Errorf("configured recovery threshold %d is incompatible with %d stored recovery shares", vaultRecoveryThreshold, len(shares))
	}
	seenShares := make(map[string]struct{}, len(shares))
	for _, share := range shares {
		if strings.TrimSpace(share) == "" {
			return "", fmt.Errorf("KMS recovery bundle contains an empty recovery share")
		}
		if _, duplicate := seenShares[share]; duplicate {
			return "", fmt.Errorf("KMS recovery bundle contains duplicate recovery shares")
		}
		seenShares[share] = struct{}{}
	}

	status, body, err := doRootVaultRequest(http.MethodGet, "/v1/sys/generate-root/attempt", nil, "")
	if err != nil {
		return "", fmt.Errorf("inspect root generation attempt: %w", err)
	}
	if status != http.StatusOK {
		return "", fmt.Errorf("inspect root generation attempt: unexpected status %d", status)
	}
	var current rootGenerationStatus
	if err := json.Unmarshal(body, &current); err != nil {
		return "", fmt.Errorf("decode root generation attempt: %w", err)
	}
	if current.Started {
		status, _, err = doRootVaultRequest(http.MethodDelete, "/v1/sys/generate-root/attempt", nil, "")
		if err != nil {
			return "", fmt.Errorf("cancel stale root generation attempt: %w", err)
		}
		if status != http.StatusNoContent {
			return "", fmt.Errorf("cancel stale root generation attempt: unexpected status %d", status)
		}
	}

	status, body, err = doRootVaultRequest(http.MethodPost, "/v1/sys/generate-root/attempt", []byte("{}"), "")
	if err != nil {
		return "", fmt.Errorf("start root generation attempt: %w", err)
	}
	if status != http.StatusOK {
		return "", fmt.Errorf("start root generation attempt: unexpected status %d", status)
	}
	var attempt rootGenerationStatus
	if err := json.Unmarshal(body, &attempt); err != nil {
		return "", fmt.Errorf("decode root generation start: %w", err)
	}
	if !attempt.Started || attempt.Nonce == "" || attempt.OTP == "" || attempt.OTPLength != len(attempt.OTP) || attempt.Complete {
		return "", fmt.Errorf("root generation start returned an invalid nonce or OTP")
	}
	if attempt.Required != vaultRecoveryThreshold {
		return "", fmt.Errorf("vault root generation requires %d shares, but configuration requires %d", attempt.Required, vaultRecoveryThreshold)
	}

	for _, share := range shares[:attempt.Required] {
		payload, marshalErr := json.Marshal(map[string]string{"key": share, "nonce": attempt.Nonce})
		if marshalErr != nil {
			return "", fmt.Errorf("marshal root generation share: %w", marshalErr)
		}
		status, body, err = doRootVaultRequest(http.MethodPost, "/v1/sys/generate-root/update", payload, "")
		if err != nil {
			return "", fmt.Errorf("submit root generation share: %w", err)
		}
		if status != http.StatusOK {
			return "", fmt.Errorf("submit root generation share: unexpected status %d", status)
		}
		var update rootGenerationStatus
		if err := json.Unmarshal(body, &update); err != nil {
			return "", fmt.Errorf("decode root generation update: %w", err)
		}
		if update.Nonce != attempt.Nonce || update.Required != attempt.Required {
			return "", fmt.Errorf("root generation update changed nonce or threshold")
		}
		if !update.Complete {
			continue
		}
		return decodeGeneratedRootToken(update.EncodedToken, attempt.OTP)
	}
	return "", fmt.Errorf("root generation did not complete after %d recovery shares", attempt.Required)
}

func decodeGeneratedRootToken(encodedToken, otp string) (string, error) {
	encoded, err := base64.RawStdEncoding.DecodeString(encodedToken)
	if err != nil {
		return "", fmt.Errorf("decode generated root token: %w", err)
	}
	if len(encoded) == 0 || len(encoded) != len(otp) {
		return "", fmt.Errorf("generated root token and OTP lengths do not match")
	}
	decoded := make([]byte, len(encoded))
	for i := range encoded {
		decoded[i] = encoded[i] ^ otp[i]
	}
	if strings.TrimSpace(string(decoded)) == "" {
		return "", fmt.Errorf("generated root token is empty")
	}
	return string(decoded), nil
}

func revokeOtherRootTokens(repairToken string) error {
	self, err := lookupSelfToken(repairToken)
	if err != nil {
		return fmt.Errorf("lookup temporary recovery root token: %w", err)
	}
	if self.Accessor == "" || !hasPolicy(self.Policies, "root") {
		return fmt.Errorf("temporary recovery token is not a root-policy token")
	}

	accessors, err := listTokenAccessors(repairToken)
	if err != nil {
		return err
	}
	selfListed := false
	for _, accessor := range accessors {
		if accessor == self.Accessor {
			selfListed = true
			continue
		}
		token, lookupErr := lookupTokenAccessor(accessor, repairToken)
		if lookupErr != nil {
			return lookupErr
		}
		if !hasPolicy(token.Policies, "root") {
			continue
		}
		if revokeErr := revokeTokenAccessor(accessor, repairToken); revokeErr != nil {
			return revokeErr
		}
	}
	if !selfListed {
		return fmt.Errorf("temporary recovery root accessor was absent from the token accessor list")
	}

	accessors, err = listTokenAccessors(repairToken)
	if err != nil {
		return fmt.Errorf("verify root-token cleanup: %w", err)
	}
	for _, accessor := range accessors {
		if accessor == self.Accessor {
			continue
		}
		token, lookupErr := lookupTokenAccessor(accessor, repairToken)
		if lookupErr != nil {
			return fmt.Errorf("verify root-token cleanup: %w", lookupErr)
		}
		if hasPolicy(token.Policies, "root") {
			return fmt.Errorf("verify root-token cleanup: root-policy token %q remains live", accessor)
		}
	}
	return nil
}

func lookupSelfToken(rootToken string) (tokenData, error) {
	status, body, err := doRootVaultRequest(http.MethodGet, "/v1/auth/token/lookup-self", nil, rootToken)
	if err != nil {
		return tokenData{}, err
	}
	if status != http.StatusOK {
		return tokenData{}, fmt.Errorf("unexpected status %d", status)
	}
	var response tokenLookupResponse
	if err := json.Unmarshal(body, &response); err != nil {
		return tokenData{}, fmt.Errorf("decode token lookup: %w", err)
	}
	return response.Data, nil
}

func listTokenAccessors(rootToken string) ([]string, error) {
	status, body, err := doRootVaultRequest("LIST", "/v1/auth/token/accessors", nil, rootToken)
	if err != nil {
		return nil, fmt.Errorf("list token accessors: %w", err)
	}
	if status != http.StatusOK {
		return nil, fmt.Errorf("list token accessors: unexpected status %d", status)
	}
	var response tokenAccessorListResponse
	if err := json.Unmarshal(body, &response); err != nil {
		return nil, fmt.Errorf("decode token accessors: %w", err)
	}
	return response.Data.Keys, nil
}

func lookupTokenAccessor(accessor, rootToken string) (tokenData, error) {
	payload, err := json.Marshal(map[string]string{"accessor": accessor})
	if err != nil {
		return tokenData{}, fmt.Errorf("marshal token accessor lookup: %w", err)
	}
	status, body, err := doRootVaultRequest(http.MethodPost, "/v1/auth/token/lookup-accessor", payload, rootToken)
	if err != nil {
		return tokenData{}, fmt.Errorf("lookup token accessor %q: %w", accessor, err)
	}
	if status != http.StatusOK {
		return tokenData{}, fmt.Errorf("lookup token accessor %q: unexpected status %d", accessor, status)
	}
	var response tokenLookupResponse
	if err := json.Unmarshal(body, &response); err != nil {
		return tokenData{}, fmt.Errorf("decode token accessor %q: %w", accessor, err)
	}
	if response.Data.Accessor != accessor {
		return tokenData{}, fmt.Errorf("lookup token accessor %q returned accessor %q", accessor, response.Data.Accessor)
	}
	return response.Data, nil
}

func revokeTokenAccessor(accessor, rootToken string) error {
	payload, err := json.Marshal(map[string]string{"accessor": accessor})
	if err != nil {
		return fmt.Errorf("marshal token accessor revocation: %w", err)
	}
	status, _, err := doRootVaultRequest(http.MethodPost, "/v1/auth/token/revoke-accessor", payload, rootToken)
	if err != nil {
		return fmt.Errorf("revoke root token accessor %q: %w", accessor, err)
	}
	if status != http.StatusNoContent {
		return fmt.Errorf("revoke root token accessor %q: unexpected status %d", accessor, status)
	}
	return nil
}

func hasPolicy(policies []string, wanted string) bool {
	for _, policy := range policies {
		if policy == wanted {
			return true
		}
	}
	return false
}

func verifyBootstrapCompletion(ctx context.Context, read encryptedSecretReader) error {
	recordJSON, err := read(ctx, bootstrapCompleteObjectName)
	if err != nil {
		return fmt.Errorf("read secure bootstrap completion: %w", err)
	}
	var record bootstrapCompletion
	if err := json.Unmarshal(recordJSON, &record); err != nil {
		return fmt.Errorf("decode secure bootstrap completion: %w", err)
	}
	if record.SchemaVersion != 1 || record.AuditPath != "cloudrun" || !record.RootTokenRevoked ||
		record.RecoveryShares < 3 || record.RecoveryThreshold < 2 ||
		record.RecoveryThreshold > record.RecoveryShares ||
		(len(record.CustodianKeySHA256) != 0 && len(record.CustodianKeySHA256) != record.RecoveryShares) {
		return fmt.Errorf("secure bootstrap completion does not prove the required audit device, root-token revocation, and recovery threshold")
	}
	seen := make(map[string]struct{}, len(record.CustodianKeySHA256))
	for _, fingerprint := range record.CustodianKeySHA256 {
		decoded, decodeErr := hex.DecodeString(fingerprint)
		if decodeErr != nil || len(decoded) != sha256.Size || fingerprint != strings.ToLower(fingerprint) {
			return fmt.Errorf("secure bootstrap completion contains an invalid custodian key fingerprint")
		}
		if _, duplicate := seen[fingerprint]; duplicate {
			return fmt.Errorf("secure bootstrap completion does not prove independent recovery custodians")
		}
		seen[fingerprint] = struct{}{}
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
	for _, name := range []string{unsealKeysObjectName, bootstrapCompleteObjectName} {
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
	if size, err := stat(ctx, rootTokenObjectName); err == nil {
		return fmt.Errorf("legacy gs://%s/%s still exists (%d bytes); revoke the retained token, replace the recovery bundle with a root-token-free copy, and remove the legacy object under dual control", gcsBucketName, rootTokenObjectName, size)
	} else if !errors.Is(err, storage.ErrObjectNotExist) {
		return fmt.Errorf("inspect legacy gs://%s/%s: %w", gcsBucketName, rootTokenObjectName, err)
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
	if body != nil && (method == http.MethodPut || method == http.MethodPost) {
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
	tokenURL, err := url.Parse(metadataTokenURL)
	if err != nil {
		return "", fmt.Errorf("parse metadata token URL: %w", err)
	}
	query := tokenURL.Query()
	query.Set("scopes", vaultProxyEmailScope)
	tokenURL.RawQuery = query.Encode()

	request, err := http.NewRequest(http.MethodGet, tokenURL.String(), nil)
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

func recoveryPGPKeysFromEnv(env string, shares, threshold int) ([]string, error) {
	if shares < 3 || threshold < 2 || threshold > shares {
		return nil, fmt.Errorf("recovery custody requires at least three shares, a threshold of at least two, and threshold no greater than shares")
	}
	raw := os.Getenv(env)
	if raw == "" {
		return nil, fmt.Errorf("%s must contain a JSON array of %d independent custodian PGP public keys", env, shares)
	}
	var keys []string
	decoder := json.NewDecoder(strings.NewReader(raw))
	if err := decoder.Decode(&keys); err != nil {
		return nil, fmt.Errorf("parse %s as a JSON string array: %w", env, err)
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		return nil, fmt.Errorf("%s must contain one JSON value", env)
	}
	if len(keys) != shares {
		return nil, fmt.Errorf("%s must contain exactly %d keys, got %d", env, shares, len(keys))
	}
	seen := make(map[[sha256.Size]byte]struct{}, len(keys))
	for i, key := range keys {
		decoded, err := base64.StdEncoding.Strict().DecodeString(key)
		if err != nil {
			return nil, fmt.Errorf("%s key %d is not strict base64: %w", env, i+1, err)
		}
		if len(decoded) < 32 || len(decoded) > 64<<10 {
			return nil, fmt.Errorf("%s key %d has an invalid decoded size", env, i+1)
		}
		digest := sha256.Sum256(decoded)
		if _, duplicate := seen[digest]; duplicate {
			return nil, fmt.Errorf("%s contains a duplicate custodian key at position %d", env, i+1)
		}
		seen[digest] = struct{}{}
	}
	return keys, nil
}

func recoveryPGPKeyDigests(keys []string) ([]string, error) {
	digests := make([]string, 0, len(keys))
	for i, key := range keys {
		decoded, err := base64.StdEncoding.Strict().DecodeString(key)
		if err != nil {
			return nil, fmt.Errorf("custodian key %d is not strict base64: %w", i+1, err)
		}
		digest := sha256.Sum256(decoded)
		digests = append(digests, hex.EncodeToString(digest[:]))
	}
	return digests, nil
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
