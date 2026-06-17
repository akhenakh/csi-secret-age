# GCP KMS Integration

The provider can fetch its age master key from GCP Cloud KMS instead of an environment variable. This keeps the plaintext key off disk and out of Kubernetes Secrets.

## How It Works

1. You generate an age identity (master key)
2. You encrypt it with GCP Cloud KMS (`gcloud kms encrypt`)
3. The base64 ciphertext blob is stored in a Kubernetes Secret
4. At startup, the provider calls `kms:Decrypt` to recover the age identity
5. The age identity is used to unlock the vault (same as `MASTER_KEY`)

The GCP KMS client uses Application Default Credentials (ADC). The IAM service account attached to the DaemonSet pods must have `roles/cloudkms.cryptoKeyDecrypter` on the target key.

## Dependency Isolation

The GCP KMS integration lives in a separate Go module (`gcpkms/`) with its own `go.mod`. The root module's `go.mod` has no GCP SDK dependencies. The two modules are only tied together by a local `go.work` file (gitignored) that you create when building with `-tags gcpkms`.

Without `go.work`, building the base project pulls zero GCP SDK packages — `go mod download` fetches only the root module's deps.

## Setup

### 1. Generate an age key

```bash
age-keygen -o key.txt
```

### 2. Encrypt with GCP KMS

```bash
gcloud kms encrypt \
  --location global \
  --keyring my-keyring \
  --key my-key \
  --plaintext-file key.txt \
  --ciphertext-file - | base64 -w0
```

Save the output — it's a base64-encoded blob.

### 3. Store in Kubernetes

```yaml
apiVersion: v1
kind: Secret
metadata:
  name: age-gcpkms-ciphertext
  namespace: kube-system
stringData:
  ciphertext: "<paste the base64 blob here>"
---
apiVersion: v1
kind: Secret
metadata:
  name: age-gcpkms-key
  namespace: kube-system
stringData:
  keyName: "projects/my-project/locations/global/keyRings/my-keyring/cryptoKeys/my-key"
```

### 4. Configure the DaemonSet

Add the `GCP_KMS_CIPHERTEXT` and `GCP_KMS_KEY_NAME` env vars to the DaemonSet container:

```yaml
- name: GCP_KMS_KEY_NAME
  valueFrom:
    secretKeyRef:
      name: age-gcpkms-key
      key: keyName
- name: GCP_KMS_CIPHERTEXT
  valueFrom:
    secretKeyRef:
      name: age-gcpkms-ciphertext
      key: ciphertext
```

Remove or comment out the `MASTER_KEY` env var.

### 5. Build with the `gcpkms` tag

First, create a local workspace so the Go toolchain finds the `gcpkms` submodule:

```bash
go work init && go work use . ./gcpkms
```

Then build:

```bash
GOEXPERIMENT=runtimesecret go build -tags gcpkms -o csi-secret-age .

# For Docker (auto-generates go.work inside the build):
docker build --build-arg GCPKMS_ENABLED=true -t age-vault-csi:latest .
```

To enable both AWS and GCP KMS:

```bash
GOEXPERIMENT=runtimesecret go build -tags "kms,gcpkms" -o csi-secret-age .

# Docker:
docker build --build-arg KMS_ENABLED=true --build-arg GCPKMS_ENABLED=true -t age-vault-csi:latest .
```

## Required IAM Permissions

The DaemonSet pods need `roles/cloudkms.cryptoKeyDecrypter` on the KMS key:

```bash
gcloud kms keys add-iam-policy-binding my-key \
  --location global \
  --keyring my-keyring \
  --member "serviceAccount:my-service-account@my-project.iam.gserviceaccount.com" \
  --role roles/cloudkms.cryptoKeyDecrypter
```

Use Workload Identity to bind the Kubernetes service account to the GCP service account.

## Fallback Behavior

If `GCP_KMS_CIPHERTEXT` or `GCP_KMS_KEY_NAME` is unset, or the KMS client fails to initialize, the provider falls back to the `MASTER_KEY` env var. This works both with and without the `gcpkms` build tag — the binary compiled without `-tags gcpkms` simply ignores the GCP env vars.
