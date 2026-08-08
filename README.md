# vault-init

The `vault-init` service automates the process of [initializing](https://www.vaultproject.io/docs/commands/operator/init.html) and [unsealing](https://www.vaultproject.io/docs/concepts/seal.html#unsealing) HashiCorp Vault instances running on [Google Cloud Platform](https://cloud.google.com).

After `vault-init` initializes a Vault server it stores only root-token-free
recovery material, encrypted using [Google Cloud KMS](https://cloud.google.com/kms),
in a user-defined [Google Cloud Storage](https://cloud.google.com/storage)
bucket. It enables a non-raw JSON audit device on Vault stdout, revokes and
verifies the initial root token, and then writes a non-secret bootstrap
completion record. The initial root token is never written to GCS.

Vault returns its initial recovery material only once. Before sending the
initialization request, this service verifies that neither destination object
already exists, that KMS can encrypt and decrypt a round-trip probe, and that
the workload can commit and read back a unique non-secret, create-only GCS
marker. The retained `vault-init-preflight/` marker is intentional because the
initializer has no object-delete permission. A graceful shutdown received before
the initialization request is sent aborts safely and leaves a one-shot job
retryable. Once the request is committed, the service ignores graceful
shutdown, retains a successful response in memory, and retries KMS and GCS with
bounded exponential backoff. GCS writes use a create-only precondition. A run
is complete only after each write is confirmed committed: either the writer
`Close` succeeds or a byte-identical create-only object is read back after an
ambiguous close result. The validated recovery response is stripped of its
root token before encryption. An unreadable or malformed response is not
persisted because it may contain a live root credential. Operators must avoid
forcibly terminating the initializer between
Vault accepting `/v1/sys/init` and the "Initialization complete" log entry.

Every run that finds Vault already initialized verifies the encrypted recovery
bundle, proves that it contains no root token, validates the bootstrap marker,
and fails if the legacy `root-token.enc` object exists. A crash after the
recovery bundle becomes durable but before audit/root revocation completes
requires a recovery-key-quorum operator repair; an automated retry cannot and
must not recover a durable root token. If `unseal-keys.json.enc` or
`bootstrap-complete.json` is missing, the process exits nonzero rather than
silently claiming success. The
default Cloud Run Job policy [retries a failed task three
times](https://cloud.google.com/run/docs/configuring/max-retries). Those retries
can bridge transient GCS errors, but they cannot repair a missing recovery
bundle. Configure a task timeout long enough for the post-initialization retry
loop because forced termination or task timeout can still interrupt secure
bootstrap.

For auto-unseal, the default is five recovery shares with a threshold of three.
Assign them to independent named custodians and test a quorum-based generate-root
procedure. A recovery bucket plus a KMS key controlled by one identity is not
independent custody.

## Usage

The `vault-init` service can run beside Vault for development or as a one-shot
job through the authenticated Vault Proxy URL. Production uses the latter so
the initializer, public proxy, and Vault runtime keep separate identities.

You can download the code and compile the binary with Go. Release images are
published as one signed multi-platform manifest to both GHCR and the public
LibOps Google Artifact Registry repository:

```text
docker pull ghcr.io/libops/vault-init:1.0.2
docker pull us-docker.pkg.dev/libops-images/public/vault-init:1.0.2
```

Both references are assembled from the same scanned amd64 and arm64 image
digests. Production Terraform must resolve the reviewed version tag and deploy
an immutable `@sha256:...` reference. GHCR is the general distribution source;
the GAR copy exists for Cloud Run.

Pull requests test the Go code and build path without publisher credentials.
Main and release publication use the SHA-pinned LibOps shared workflow, the
repository-scoped `github@libops-images` workload identity, and explicit GitHub
secrets. The workflow scans each native image before any stable tag is written,
checks GHCR/GAR manifest parity, then keylessly signs and verifies both final
manifests. It does not publish build-provenance attestations.

To use this as part of a Kubernetes Vault Deployment:

```yaml
containers:
- name: vault-init
  image: ghcr.io/libops/vault-init@sha256:REVIEWED_MANIFEST_DIGEST
  imagePullPolicy: IfNotPresent
  env:
  - name: GCS_BUCKET_NAME
    value: my-gcs-bucket
  - name: KMS_KEY_ID
    value: projects/my-project/locations/my-location/cryptoKeys/my-key
```

## Configuration

The `vault-init` service supports the following environment variables for configuration:

- `CHECK_INTERVAL` ("10s") - The time duration between Vault health checks. Set
  this to zero or a negative number to check, initialize or unseal once and
  exit. One-shot failures return a nonzero status.

- `VAULT_ADDR` ("https://127.0.0.1:8200") - Vault API address. HTTPS is required
  because the service sends its Google access token in the `X-Admin-Token`
  header. The address must not contain credentials, a path, query, or fragment.
  Metadata token retrieval bypasses environment-configured HTTP proxies and does
  not follow redirects. The token requests only the
  `https://www.googleapis.com/auth/userinfo.email` scope required for Vault
  Proxy to verify the service-account email; KMS and GCS use separate
  application-default credentials.

- `VAULT_ALLOW_PLAINTEXT` (false) - Permit an `http://` Vault address. This is an
  explicit development-only escape hatch because it exposes the Google access
  token and Vault initialization traffic to interception.

- `VAULT_CLIENT_TIMEOUT` ("60s") - Timeout for Vault API requests. An overly
  short timeout can make the result of the one-time initialization request
  ambiguous. Redirects are never followed because every Vault request carries
  the privileged Google access token and initialization redirects would also
  make commit state ambiguous.

- `GCS_BUCKET_NAME` - The Google Cloud Storage bucket where root-token-free
  recovery material and the non-secret completion record are stored.

- `KMS_KEY_ID` - The Google Cloud KMS key ID used to encrypt and decrypt the
  Vault recovery bundle.

- `VAULT_SECRET_SHARES` (5) - The number of human shares to create.

- `VAULT_SECRET_THRESHOLD` (3) - The number of human shares required to unseal.

- `VAULT_AUTO_UNSEAL` (true) - Use Vault 1.0 native auto-unsealing directly. You must
  set the seal configuration in Vault's configuration.

- `VAULT_STORED_SHARES` (1) - Number of shares to store on KMS. Only applies to
  Vault 1.0 native auto-unseal.

- `VAULT_RECOVERY_SHARES` (5) - Number of recovery shares to generate. Only
  applies to Vault 1.0 native auto-unseal.

- `VAULT_RECOVERY_THRESHOLD` (3) - Number of recovery shares needed to authorize recovery operations.
  Only applies to Vault 1.0 native auto-unseal.

- `VAULT_RECOVERY_PGP_KEYS` - Required with auto-unseal. A JSON array whose
  length equals `VAULT_RECOVERY_SHARES`; each entry is a distinct
  base64-encoded binary PGP public key owned by an independent custodian. Vault
  encrypts each returned recovery share to the corresponding key. Private PGP
  keys must never be provided to this service.

- `VAULT_SKIP_VERIFY` (false) - Disable TLS validation when connecting. Setting
  to true is highly discouraged. TLS 1.2 or newer is required by default.

- `VAULT_CACERT` ("") - Path on disk to the CA _file_ to use for verifying TLS
  connections to Vault.

- `VAULT_CAPATH` ("") - Path on disk to a directory containing the CAs to use
  for verifying TLS connections to Vault. `VAULT_CACERT` takes precedence.

- `VAULT_TLS_SERVER_NAME` ("") - Custom SNI hostname to use when validating TLS
  connections to Vault.

### Example Values

```
CHECK_INTERVAL="30s"
GCS_BUCKET_NAME="vault-storage"
KMS_KEY_ID="projects/my-project/locations/global/keyRings/my-keyring/cryptoKeys/key"
```

### IAM &amp; Permissions

The `vault-init` service uses the official Google Cloud Golang SDK. This means
it supports the common ways of [providing credentials to GCP][cloud-creds].

To use this service, the service account must have the following minimum
scope(s):

```text
https://www.googleapis.com/auth/cloudkms
https://www.googleapis.com/auth/devstorage.read_write
```

Additionally, the service account must have the following minimum role(s):

```text
roles/cloudkms.cryptoKeyEncrypterDecrypter
roles/storage.objectCreator
roles/storage.objectViewer
```

Object read access is intentional: it lets the initializer refuse to overwrite
older recovery material and verify an idempotent retry when a successful GCS
commit loses its client response. Object Creator plus Object Viewer provides
the required create/read permissions without granting this workload delete or
overwrite access. Use a dedicated bucket for each Vault deployment and protect
it with retention, versioning, restricted administration, and an independently
tested recovery procedure.

Existing deployments that contain `root-token.enc` or a root token inside
`unseal-keys.json.enc` must be migrated under dual control: decrypt in a
restricted recovery session, revoke the retained token, write a root-token-free
bundle, remove the legacy object, enable and verify the `cloudrun/` stdout audit
device, and write the completion marker. Do not copy decrypted material through
Terraform, CI, tickets, chat, or shell arguments.

For more information on service accounts, please see the
[Google Cloud Service Accounts documentation][service-accounts].

[cloud-creds]: https://cloud.google.com/docs/authentication/production#providing_credentials_to_your_application
[service-accounts]: https://cloud.google.com/compute/docs/access/service-accounts
