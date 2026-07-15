package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"cloud.google.com/go/storage"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return f(request)
}

type scriptedWriteCloser struct {
	written   int
	writeErr  error
	closeErr  error
	closed    int
	callOrder *[]string
}

func (w *scriptedWriteCloser) Write(_ []byte) (int, error) {
	if w.callOrder != nil {
		*w.callOrder = append(*w.callOrder, "write")
	}
	return w.written, w.writeErr
}

func (w *scriptedWriteCloser) Close() error {
	w.closed++
	if w.callOrder != nil {
		*w.callOrder = append(*w.callOrder, "close")
	}
	return w.closeErr
}

func TestRetryInitializationPersistenceRetainsOneTimeResponse(t *testing.T) {
	initResponse := []byte(`{"keys_base64":["key"],"root_token":"root"}`)
	encryptCalls := 0
	encrypt := func(_ context.Context, plaintext []byte) ([]byte, error) {
		encryptCalls++
		if encryptCalls == 1 {
			return nil, errors.New("transient KMS failure")
		}
		return append([]byte("encrypted:"), plaintext...), nil
	}

	var writes []struct {
		name string
		data []byte
	}
	rootWriteAttempts := 0
	store := func(_ context.Context, name string, ciphertext []byte) error {
		writes = append(writes, struct {
			name string
			data []byte
		}{name: name, data: bytes.Clone(ciphertext)})
		if name == rootTokenObjectName {
			rootWriteAttempts++
			if rootWriteAttempts == 1 {
				return errors.New("transient GCS failure")
			}
		}
		return nil
	}

	var waits []time.Duration
	err := retryInitializationPersistence(
		initResponse,
		"root",
		encrypt,
		store,
		func(delay time.Duration) { waits = append(waits, delay) },
	)
	if err != nil {
		t.Fatal(err)
	}

	if encryptCalls != 3 {
		t.Fatalf("encrypt calls = %d, want 3", encryptCalls)
	}
	if !reflect.DeepEqual(waits, []time.Duration{time.Second, 2 * time.Second}) {
		t.Fatalf("retry delays = %v", waits)
	}
	wantWrites := []struct {
		name string
		data []byte
	}{
		{name: unsealKeysObjectName, data: append([]byte("encrypted:"), initResponse...)},
		{name: rootTokenObjectName, data: []byte("encrypted:root")},
		{name: rootTokenObjectName, data: []byte("encrypted:root")},
	}
	if !reflect.DeepEqual(writes, wantWrites) {
		t.Fatalf("writes = %#v, want %#v", writes, wantWrites)
	}
}

func TestRetryInitializationPersistenceMakesRecoveryBundleDurableBeforeRootTokenWork(t *testing.T) {
	initResponse := []byte(`{"keys_base64":["key"],"root_token":"root"}`)
	var events []string
	err := retryInitializationPersistence(
		initResponse,
		"root",
		func(_ context.Context, plaintext []byte) ([]byte, error) {
			if bytes.Equal(plaintext, initResponse) {
				events = append(events, "encrypt bundle")
				return []byte("bundle"), nil
			}
			events = append(events, "encrypt root")
			return []byte("token"), nil
		},
		func(_ context.Context, name string, _ []byte) error {
			events = append(events, "store "+name)
			return nil
		},
		func(time.Duration) { t.Fatal("unexpected retry") },
	)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{
		"encrypt bundle",
		"store " + unsealKeysObjectName,
		"encrypt root",
		"store " + rootTokenObjectName,
	}
	if !reflect.DeepEqual(events, want) {
		t.Fatalf("events = %v, want %v", events, want)
	}
}

func TestRetryInitializationPersistencePreservesUnexpectedResponse(t *testing.T) {
	response := []byte(`{"unexpected":"response"}`)
	var writes []string
	err := retryInitializationPersistence(
		response,
		"",
		func(_ context.Context, plaintext []byte) ([]byte, error) {
			return append([]byte("encrypted:"), plaintext...), nil
		},
		func(_ context.Context, name string, _ []byte) error {
			writes = append(writes, name)
			return nil
		},
		func(time.Duration) { t.Fatal("unexpected retry") },
	)
	if err == nil || !strings.Contains(err.Error(), "complete encrypted response is durable") {
		t.Fatalf("error = %v, want durable-bundle warning", err)
	}
	if !reflect.DeepEqual(writes, []string{unsealKeysObjectName}) {
		t.Fatalf("writes = %v, want only recovery bundle", writes)
	}
}

func TestProcessTLSConfigReadsCertificatesFromCAPath(t *testing.T) {
	server := httptest.NewTLSServer(nil)
	server.Close()
	certificate := server.Certificate()
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certificate.Raw})

	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "ca.pem"), certPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(dir, "ignored"), 0o700); err != nil {
		t.Fatal(err)
	}

	cfg := &tls.Config{}
	if err := processTLSConfig(cfg, "vault.internal", "", dir); err != nil {
		t.Fatal(err)
	}
	if cfg.ServerName != "vault.internal" {
		t.Fatalf("server name = %q", cfg.ServerName)
	}
	if cfg.RootCAs == nil {
		t.Fatal("root CA pool was not configured")
	}
	wantRoots := x509.NewCertPool()
	if !wantRoots.AppendCertsFromPEM(certPEM) {
		t.Fatal("failed to construct expected root CA pool")
	}
	if !cfg.RootCAs.Equal(wantRoots) {
		t.Fatal("configured root CA pool does not match the CA path")
	}
}

func TestDurationFromEnvironmentAcceptsSecondsAndGoDurations(t *testing.T) {
	t.Setenv("TEST_DURATION", "30")
	if got := durFromEnv("TEST_DURATION", 0); got != 30*time.Second {
		t.Fatalf("numeric duration = %s", got)
	}
	t.Setenv("TEST_DURATION", "1500ms")
	if got := durFromEnv("TEST_DURATION", 0); got != 1500*time.Millisecond {
		t.Fatalf("Go duration = %s", got)
	}
}

func TestValidateVaultAddress(t *testing.T) {
	tests := []struct {
		name           string
		address        string
		allowPlaintext bool
		want           string
		wantError      string
	}{
		{name: "https", address: "https://vault.internal:8200", want: "https://vault.internal:8200"},
		{name: "trim and normalize", address: " HTTPS://vault.internal:8200/ ", want: "https://vault.internal:8200"},
		{name: "explicit plaintext", address: "http://127.0.0.1:8200", allowPlaintext: true, want: "http://127.0.0.1:8200"},
		{name: "plaintext rejected", address: "http://vault.internal:8200", wantError: "plaintext HTTP"},
		{name: "relative rejected", address: "vault.internal:8200", wantError: "absolute URL"},
		{name: "credentials rejected", address: "https://userinfo@vault.internal", wantError: "must not contain credentials"},
		{name: "path rejected", address: "https://vault.internal/base", wantError: "must not contain a path"},
		{name: "query rejected", address: "https://vault.internal?mode=test", wantError: "must not contain a query"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := validateVaultAddress(tt.address, tt.allowPlaintext)
			if tt.wantError != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantError) {
					t.Fatalf("error = %v, want text %q", err, tt.wantError)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if got != tt.want {
				t.Fatalf("address = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestVaultClientRefusesRedirects(t *testing.T) {
	redirected := false
	target := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		redirected = true
	}))
	defer target.Close()

	source := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
		response.Header().Set("Location", target.URL)
		response.WriteHeader(http.StatusTemporaryRedirect)
	}))
	defer source.Close()

	client := &http.Client{CheckRedirect: refuseHTTPRedirect}
	request, err := http.NewRequest(http.MethodPut, source.URL, strings.NewReader(`{"initialize":true}`))
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("X-Admin-Token", "privileged-token")

	response, err := client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusTemporaryRedirect {
		t.Fatalf("status = %d, want %d", response.StatusCode, http.StatusTemporaryRedirect)
	}
	if redirected {
		t.Fatal("Vault client followed a redirect carrying the admin token")
	}
}

func TestMetadataClientDoesNotUseProxyOrRedirects(t *testing.T) {
	client := newMetadataHTTPClient()
	transport, ok := client.Transport.(*http.Transport)
	if !ok {
		t.Fatalf("metadata transport type = %T", client.Transport)
	}
	if transport.Proxy != nil {
		t.Fatal("metadata client permits an environment-configured HTTP proxy")
	}
	if !transport.DisableKeepAlives {
		t.Fatal("metadata client retains an idle plain-HTTP connection")
	}
	if client.CheckRedirect == nil {
		t.Fatal("metadata client permits redirects")
	}
	if err := client.CheckRedirect(nil, nil); !errors.Is(err, http.ErrUseLastResponse) {
		t.Fatalf("redirect error = %v, want http.ErrUseLastResponse", err)
	}
}

func TestVaultHealthRequestDoesNotMintOrSendAdminToken(t *testing.T) {
	originalMetadataClient := metadataClient
	t.Cleanup(func() {
		metadataClient = originalMetadataClient
	})

	metadataCalls := 0
	metadataClient = &http.Client{
		Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
			metadataCalls++
			return nil, errors.New("metadata must not be called for health")
		}),
	}

	request, err := newVaultRequest(http.MethodHead, "https://vault.internal/v1/sys/health", nil)
	if err != nil {
		t.Fatal(err)
	}
	if metadataCalls != 0 {
		t.Fatalf("metadata calls = %d, want 0", metadataCalls)
	}
	if token := request.Header.Get("X-Admin-Token"); token != "" {
		t.Fatalf("health request carries X-Admin-Token %q", token)
	}
	if accept := request.Header.Get("Accept"); accept != "application/json" {
		t.Fatalf("Accept = %q, want application/json", accept)
	}
}

func TestRetryDelayIsCapped(t *testing.T) {
	if got := nextRetryDelay(45 * time.Second); got != maxSecretRetryDelay {
		t.Fatalf("next retry delay = %s", got)
	}
}

func TestHealthStatusIndicatesInitialized(t *testing.T) {
	tests := map[int]bool{
		200: true,
		429: true,
		472: true,
		473: true,
		501: false,
		503: true,
		500: false,
	}
	for statusCode, want := range tests {
		if got := healthStatusIndicatesInitialized(statusCode); got != want {
			t.Errorf("status %d: initialized = %t, want %t", statusCode, got, want)
		}
	}
}

func TestShutdownRequestedConsumesPendingSignal(t *testing.T) {
	shutdown := make(chan os.Signal, 1)
	if shutdownRequested(shutdown) {
		t.Fatal("empty signal channel reported shutdown")
	}
	shutdown <- os.Interrupt
	if !shutdownRequested(shutdown) {
		t.Fatal("pending signal was not observed")
	}
	if shutdownRequested(shutdown) {
		t.Fatal("signal was not consumed")
	}
}

func TestShutdownExitCodeKeepsOneShotJobsRetryable(t *testing.T) {
	if got := shutdownExitCode(true); got != 1 {
		t.Fatalf("shutdownExitCode(true) = %d, want 1", got)
	}
	if got := shutdownExitCode(false); got != 0 {
		t.Fatalf("shutdownExitCode(false) = %d, want 0", got)
	}
}

func TestVerifyStoredRecoveryMaterial(t *testing.T) {
	lookupFailure := errors.New("storage unavailable")
	tests := []struct {
		name      string
		sizes     map[string]int64
		errors    map[string]error
		wantError string
	}{
		{
			name: "complete",
			sizes: map[string]int64{
				unsealKeysObjectName: 512,
				rootTokenObjectName:  128,
			},
		},
		{
			name:      "missing mandatory recovery bundle",
			sizes:     map[string]int64{rootTokenObjectName: 128},
			wantError: unsealKeysObjectName + " is missing",
		},
		{
			name:      "missing convenience root token",
			sizes:     map[string]int64{unsealKeysObjectName: 512},
			wantError: rootTokenObjectName + " is missing",
		},
		{
			name: "empty mandatory recovery bundle",
			sizes: map[string]int64{
				unsealKeysObjectName: 0,
				rootTokenObjectName:  128,
			},
			wantError: unsealKeysObjectName + " is empty",
		},
		{
			name: "empty convenience root token",
			sizes: map[string]int64{
				unsealKeysObjectName: 512,
				rootTokenObjectName:  0,
			},
			wantError: rootTokenObjectName + " is empty",
		},
		{
			name:      "lookup failure",
			errors:    map[string]error{unsealKeysObjectName: lookupFailure},
			wantError: lookupFailure.Error(),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			stat := func(_ context.Context, name string) (int64, error) {
				if err := tt.errors[name]; err != nil {
					return 0, err
				}
				if size, ok := tt.sizes[name]; ok {
					return size, nil
				}
				return 0, storage.ErrObjectNotExist
			}

			err := verifyStoredRecoveryMaterial(context.Background(), stat)
			if tt.wantError == "" {
				if err != nil {
					t.Fatal(err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tt.wantError) {
				t.Fatalf("error = %v, want text %q", err, tt.wantError)
			}
		})
	}
}

func TestRestoreRootTokenObjectFromDurableResponse(t *testing.T) {
	response := []byte(`{"keys_base64":["key"],"root_token":"root"}`)
	var storedName string
	var storedData []byte
	err := restoreRootTokenObject(
		context.Background(),
		func(_ context.Context, name string) ([]byte, error) {
			if name != unsealKeysObjectName {
				t.Fatalf("read object = %q", name)
			}
			return append([]byte("encrypted:"), response...), nil
		},
		func(_ context.Context, ciphertext []byte) ([]byte, error) {
			return bytes.TrimPrefix(ciphertext, []byte("encrypted:")), nil
		},
		func(_ context.Context, plaintext []byte) ([]byte, error) {
			return append([]byte("encrypted:"), plaintext...), nil
		},
		func(_ context.Context, name string, data []byte) error {
			storedName = name
			storedData = bytes.Clone(data)
			return nil
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	if storedName != rootTokenObjectName {
		t.Fatalf("stored object = %q", storedName)
	}
	if string(storedData) != "encrypted:root" {
		t.Fatalf("stored data = %q", storedData)
	}
}

func TestRestoreRootTokenObjectRejectsUnusableResponse(t *testing.T) {
	err := restoreRootTokenObject(
		context.Background(),
		func(context.Context, string) ([]byte, error) { return []byte("encrypted"), nil },
		func(context.Context, []byte) ([]byte, error) { return []byte(`{"keys_base64":["key"]}`), nil },
		func(context.Context, []byte) ([]byte, error) {
			t.Fatal("root token encryption ran for unusable response")
			return nil, nil
		},
		func(context.Context, string, []byte) error {
			t.Fatal("root token write ran for unusable response")
			return nil
		},
	)
	if err == nil || !strings.Contains(err.Error(), "did not contain a root token") {
		t.Fatalf("error = %v, want missing root token", err)
	}
}

func TestPreflightInitializationChecksTargetsBeforeKMS(t *testing.T) {
	encryptCalls := 0
	stat := func(_ context.Context, name string) (int64, error) {
		if name == unsealKeysObjectName {
			return 10, nil
		}
		return 0, storage.ErrObjectNotExist
	}
	encrypt := func(_ context.Context, _ []byte) ([]byte, error) {
		encryptCalls++
		return []byte("ciphertext"), nil
	}
	decrypt := func(_ context.Context, _ []byte) ([]byte, error) {
		t.Fatal("KMS decrypt ran after existing recovery material was found")
		return nil, nil
	}
	testPermissions := func(_ context.Context, _ []string) ([]string, error) {
		t.Fatal("permission check ran after existing recovery material was found")
		return nil, nil
	}

	err := preflightInitialization(context.Background(), stat, testPermissions, encrypt, decrypt, func(context.Context) error {
		t.Fatal("storage round trip ran after existing recovery material was found")
		return nil
	})
	if err == nil || !strings.Contains(err.Error(), "already exists") {
		t.Fatalf("error = %v, want existing-object refusal", err)
	}
	if encryptCalls != 0 {
		t.Fatalf("KMS called %d times after storage preflight failure", encryptCalls)
	}
}

func TestPreflightInitializationRequiresWorkingKMS(t *testing.T) {
	stat := func(_ context.Context, _ string) (int64, error) {
		return 0, storage.ErrObjectNotExist
	}
	testPermissions := func(_ context.Context, permissions []string) ([]string, error) {
		return permissions, nil
	}
	encrypt := func(_ context.Context, plaintext []byte) ([]byte, error) {
		if string(plaintext) != kmsPreflightPlaintext {
			t.Fatalf("preflight plaintext = %q", plaintext)
		}
		return nil, errors.New("KMS unavailable")
	}
	decrypt := func(_ context.Context, _ []byte) ([]byte, error) {
		t.Fatal("KMS decrypt ran after encryption failed")
		return nil, nil
	}

	err := preflightInitialization(context.Background(), stat, testPermissions, encrypt, decrypt, func(context.Context) error {
		t.Fatal("storage round trip ran after KMS failure")
		return nil
	})
	if err == nil || !strings.Contains(err.Error(), "verify KMS encryption") {
		t.Fatalf("error = %v, want KMS preflight failure", err)
	}
}

func TestPreflightInitializationRequiresCreateAndReadPermissions(t *testing.T) {
	stat := func(_ context.Context, _ string) (int64, error) {
		return 0, storage.ErrObjectNotExist
	}
	testPermissions := func(_ context.Context, _ []string) ([]string, error) {
		return []string{"storage.objects.get"}, nil
	}
	encryptCalls := 0
	encrypt := func(_ context.Context, _ []byte) ([]byte, error) {
		encryptCalls++
		return []byte("ciphertext"), nil
	}
	decrypt := func(_ context.Context, _ []byte) ([]byte, error) {
		t.Fatal("KMS decrypt ran after permission failure")
		return nil, nil
	}

	err := preflightInitialization(context.Background(), stat, testPermissions, encrypt, decrypt, func(context.Context) error {
		t.Fatal("storage round trip ran after permission failure")
		return nil
	})
	if err == nil || !strings.Contains(err.Error(), "missing storage.objects.create") {
		t.Fatalf("error = %v, want missing create permission", err)
	}
	if encryptCalls != 0 {
		t.Fatalf("KMS called %d times after permission failure", encryptCalls)
	}
}

func TestPreflightInitializationRequiresWorkingKMSDecryption(t *testing.T) {
	stat := func(_ context.Context, _ string) (int64, error) {
		return 0, storage.ErrObjectNotExist
	}
	testPermissions := func(_ context.Context, permissions []string) ([]string, error) {
		return permissions, nil
	}
	encrypt := func(_ context.Context, _ []byte) ([]byte, error) {
		return []byte("ciphertext"), nil
	}
	decrypt := func(_ context.Context, ciphertext []byte) ([]byte, error) {
		if string(ciphertext) != "ciphertext" {
			t.Fatalf("ciphertext = %q", ciphertext)
		}
		return nil, errors.New("decrypt permission denied")
	}

	err := preflightInitialization(context.Background(), stat, testPermissions, encrypt, decrypt, func(context.Context) error {
		t.Fatal("storage round trip ran after KMS decrypt failure")
		return nil
	})
	if err == nil || !strings.Contains(err.Error(), "verify KMS decryption") {
		t.Fatalf("error = %v, want KMS decryption preflight failure", err)
	}
}

func TestPreflightInitializationRejectsKMSRoundTripMismatch(t *testing.T) {
	stat := func(_ context.Context, _ string) (int64, error) {
		return 0, storage.ErrObjectNotExist
	}
	testPermissions := func(_ context.Context, permissions []string) ([]string, error) {
		return permissions, nil
	}
	encrypt := func(_ context.Context, _ []byte) ([]byte, error) {
		return []byte("ciphertext"), nil
	}
	decrypt := func(_ context.Context, _ []byte) ([]byte, error) {
		return []byte("different plaintext"), nil
	}

	err := preflightInitialization(context.Background(), stat, testPermissions, encrypt, decrypt, func(context.Context) error {
		t.Fatal("storage round trip ran after KMS mismatch")
		return nil
	})
	if err == nil || !strings.Contains(err.Error(), "round-trip plaintext mismatch") {
		t.Fatalf("error = %v, want KMS round-trip failure", err)
	}
}

func TestPreflightInitializationSucceeds(t *testing.T) {
	stat := func(_ context.Context, _ string) (int64, error) {
		return 0, storage.ErrObjectNotExist
	}
	testPermissions := func(_ context.Context, permissions []string) ([]string, error) {
		return permissions, nil
	}
	encrypt := func(_ context.Context, plaintext []byte) ([]byte, error) {
		return append([]byte("encrypted:"), plaintext...), nil
	}
	decrypt := func(_ context.Context, ciphertext []byte) ([]byte, error) {
		return bytes.TrimPrefix(ciphertext, []byte("encrypted:")), nil
	}

	storageRoundTrips := 0
	if err := preflightInitialization(context.Background(), stat, testPermissions, encrypt, decrypt, func(context.Context) error {
		storageRoundTrips++
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if storageRoundTrips != 1 {
		t.Fatalf("storage round trips = %d, want 1", storageRoundTrips)
	}
}

func TestVerifyStorageRoundTrip(t *testing.T) {
	tests := []struct {
		name      string
		storeErr  error
		readData  []byte
		readErr   error
		wantError string
	}{
		{name: "success", readData: []byte("marker")},
		{name: "create failure", storeErr: errors.New("close failed"), wantError: "create marker object"},
		{name: "read failure", readErr: errors.New("read failed"), wantError: "read marker object"},
		{name: "content mismatch", readData: []byte("different"), wantError: "content mismatch"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			storeCalls := 0
			readCalls := 0
			err := verifyStorageRoundTrip(
				context.Background(),
				"vault-init-preflight/test",
				[]byte("marker"),
				func(_ context.Context, name string, data []byte) error {
					storeCalls++
					if name != "vault-init-preflight/test" || string(data) != "marker" {
						t.Fatalf("store(%q, %q)", name, data)
					}
					return tt.storeErr
				},
				func(_ context.Context, name string) ([]byte, error) {
					readCalls++
					if name != "vault-init-preflight/test" {
						t.Fatalf("read(%q)", name)
					}
					return tt.readData, tt.readErr
				},
			)
			if tt.wantError == "" && err != nil {
				t.Fatal(err)
			}
			if tt.wantError != "" && (err == nil || !strings.Contains(err.Error(), tt.wantError)) {
				t.Fatalf("error = %v, want %q", err, tt.wantError)
			}
			if storeCalls != 1 {
				t.Fatalf("store calls = %d, want 1", storeCalls)
			}
			wantReadCalls := 1
			if tt.storeErr != nil {
				wantReadCalls = 0
			}
			if readCalls != wantReadCalls {
				t.Fatalf("read calls = %d, want %d", readCalls, wantReadCalls)
			}
		})
	}
}

func TestVerifyStorageRoundTripRejectsEmptyMarker(t *testing.T) {
	err := verifyStorageRoundTrip(
		context.Background(),
		"vault-init-preflight/test",
		nil,
		func(context.Context, string, []byte) error {
			t.Fatal("empty marker was stored")
			return nil
		},
		func(context.Context, string) ([]byte, error) {
			t.Fatal("empty marker was read")
			return nil, nil
		},
	)
	if err == nil || !strings.Contains(err.Error(), "marker is empty") {
		t.Fatalf("error = %v, want empty marker", err)
	}
}

func TestWriteObjectOnce(t *testing.T) {
	tests := []struct {
		name                string
		writer              scriptedWriteCloser
		wantCommitUncertain bool
		wantError           error
	}{
		{name: "success", writer: scriptedWriteCloser{written: 6}},
		{name: "short write", writer: scriptedWriteCloser{written: 3}, wantError: io.ErrShortWrite},
		{name: "write failure", writer: scriptedWriteCloser{writeErr: errors.New("write failed")}, wantError: errors.New("write failed")},
		{name: "ambiguous close failure", writer: scriptedWriteCloser{written: 6, closeErr: errors.New("close failed")}, wantCommitUncertain: true, wantError: errors.New("close failed")},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			callOrder := []string{}
			tt.writer.callOrder = &callOrder
			cancelCalls := 0
			commitUncertain, err := writeObjectOnce(&tt.writer, func() {
				cancelCalls++
				callOrder = append(callOrder, "cancel")
			}, []byte("marker"))
			if commitUncertain != tt.wantCommitUncertain {
				t.Fatalf("commit uncertainty = %v, want %v", commitUncertain, tt.wantCommitUncertain)
			}
			if tt.wantError == nil && err != nil {
				t.Fatal(err)
			}
			if tt.wantError != nil && (err == nil || err.Error() != tt.wantError.Error()) {
				t.Fatalf("error = %v, want %v", err, tt.wantError)
			}
			if cancelCalls != 1 || tt.writer.closed != 1 {
				t.Fatalf("cancel calls = %d, close calls = %d; want one each", cancelCalls, tt.writer.closed)
			}
			if tt.name == "short write" || tt.name == "write failure" {
				wantOrder := []string{"write", "cancel", "close"}
				if !reflect.DeepEqual(callOrder, wantOrder) {
					t.Fatalf("call order = %v, want %v", callOrder, wantOrder)
				}
			}
		})
	}
}
