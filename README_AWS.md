# AWS KMS Integration

The provider can fetch its age master key from AWS KMS instead of storing it as an environment variable or file. This keeps the plaintext key off disk and out of Kubernetes Secrets.

## How It Works

1. You generate an age identity (master key)
2. You encrypt it with AWS KMS (`kms:Encrypt`)
3. The base64 ciphertext blob is stored in a Kubernetes Secret
4. At startup, the provider calls `kms:Decrypt` to recover the age identity
5. The age identity is used to unlock the vault (same as `MASTER_KEY`)

The AWS KMS client uses the standard AWS credential chain (env vars, instance profile, `~/.aws/credentials`, etc.). The IAM role attached to the DaemonSet pods must have `kms:Decrypt` permission on the target KMS key.

## Dependency Isolation

The KMS integration lives in a separate Go module (`awskms/`) with its own `go.mod`. The root module's `go.mod` has no AWS SDK dependencies. The two modules are only tied together by a local `go.work` file (gitignored) that you create when building with `-tags kms`.

Without `go.work`, building the base project pulls zero AWS SDK packages — `go mod download` fetches only the root module's deps.

## Setup

### 1. Generate an age key

```bash
age-keygen -o key.txt
```

### 2. Encrypt with AWS KMS

```bash
aws kms encrypt \
  --key-id arn:aws:kms:<region>:<account>:key/<key-id> \
  --plaintext fileb://key.txt \
  --output text \
  --query CiphertextBlob
```

Save the output — it's a base64-encoded blob.

### 3. Store in Kubernetes

```yaml
apiVersion: v1
kind: Secret
metadata:
  name: age-kms-ciphertext
  namespace: kube-system
stringData:
  ciphertext: "<paste the base64 blob here>"
```

### 4. Configure the DaemonSet

Add the `KMS_CIPHERTEXT` env var to the DaemonSet container (see `deploy.yaml` for the commented-out example):

```yaml
- name: KMS_CIPHERTEXT
  valueFrom:
    secretKeyRef:
      name: age-kms-ciphertext
      key: ciphertext
```

Alternatively, read the ciphertext from a mounted file using `KMS_CIPHERTEXT_FILE` (preferred — avoids exposing the value in environment variables):

```yaml
volumes:
  - name: kms-ciphertext
    secret:
      secretName: age-kms-ciphertext
containers:
  - name: csi-secret-age
    volumeMounts:
      - name: kms-ciphertext
        mountPath: /etc/csi-secret-age/kms
        readOnly: true
    env:
      - name: KMS_CIPHERTEXT_FILE
        value: /etc/csi-secret-age/kms/ciphertext
```

Remove or comment out the `MASTER_KEY` env var — the KMS provider takes precedence when `KMS_CIPHERTEXT` (or `KMS_CIPHERTEXT_FILE`) is set.

### 5. Build with the `kms` tag

First, create a local workspace so the Go toolchain finds the `kms` submodule:

```bash
go work init && go work use . ./awskms
```

Then build:

```bash
GOEXPERIMENT=runtimesecret go build -tags kms -o csi-secret-age .

# For Docker (auto-generates go.work inside the build):
docker build --build-arg KMS_ENABLED=true -t csi-secret-age:latest .
```

## Required IAM Permissions

The DaemonSet pods need `kms:Decrypt` on the KMS key:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": "kms:Decrypt",
      "Resource": "arn:aws:kms:<region>:<account>:key/<key-id>"
    }
  ]
}
```

Attach this policy via IRSA (IAM Roles for Service Accounts) or the node's instance profile.

## Fallback Behavior

If neither `KMS_CIPHERTEXT` nor `KMS_CIPHERTEXT_FILE` is set, or the KMS client fails to initialize, the provider falls back to the `MASTER_KEY` (or `MASTER_KEY_FILE`) env var. This works both with and without the `kms` build tag — the binary compiled without `-tags kms` simply ignores the KMS fields.
