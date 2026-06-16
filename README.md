# Age-Encrypted Vault CSI Provider

A secure, zero-infrastructure Secrets Store CSI provider for Kubernetes. It stores your secrets in a centralized hierarchical tree, encrypts the entire tree using `filippo.io/age`, and persists it transparently as a standard Kubernetes Secret.

Designed for maximum security, it features an encrypted-at-rest backend, a secure locked state on startup, and hardware-level memory wiping using Go's `runtime/secret` experiment.

No external databases or heavy Vault installations are required.

## Features
* **Zero Infrastructure:** State is saved as an encrypted blob inside a standard Kubernetes Secret. Backing up your cluster naturally backs up your secrets.
* **Cold Start / Lock Mode:** The provider starts in a "Locked" state. It can be unlocked manually via the Web UI, via an environment variable, or seamlessly via Cloud KMS integrations.
* **Granular Access Control:** Define exactly which Namespaces and ServiceAccounts can read specific paths in your secret tree.
* **Web UI JWT Permissions:** In production (non-dev mode), the Web UI can enforce JWT-based RBAC so users only see and manage the parts of the tree they own.
* **Modern Cryptography:** Powered by the modern, secure `filippo.io/age` encryption standard.
* **Cloud KMS Ready:** Extensible `MasterKeyProvider` interface allows fetching the master unlock key from AWS KMS, GCP KMS, or Azure KeyVault.
* **Memory Safe:** Built using Go 1.24+ `runtime/secret` experiment. All decryption, JSON parsing, and string manipulation happen inside a secure execution enclave. Plaintext secrets are strictly zeroed out from heap memory when no longer needed.

---

## Architecture & Lifecycle

1. **Deployment:** The CSI provider is deployed as a DaemonSet. If no Master Key is provided, it starts in **Locked** mode.
2. **Unlocking:** An administrator provides the Master Key via the local Web UI, or the system auto-fetches it via a Cloud KMS plugin.
3. **Administration:** Using the local Web UI, administrators can blind-write new secrets and define Access Control Lists (ACLs). The Web UI masks all values and strips plaintext before rendering HTML to prevent memory leaks.
4. **Encryption:** The Provider serializes and encrypts the tree using the `age` public key, storing it in `kube-system/age-vault-backend`.
5. **Mounting:** When a Pod requests a secret, the Provider dynamically decrypts the Vault Tree *in-memory*, evaluates the ACL against the requesting Pod's Namespace/ServiceAccount, and securely mounts the secret into the Pod.

---

## Prerequisites

1. Kubernetes cluster.
2. The [Secrets Store CSI Driver](https://secrets-store-csi-driver.sigs.k8s.io/) installed:
   ```bash
   helm repo add secrets-store-csi-driver https://kubernetes-sigs.github.io/secrets-store-csi-driver/charts
   helm install csi-secrets-store secrets-store-csi-driver/secrets-store-csi-driver --namespace kube-system --set syncSecret.enabled=true
   ```
3. `age` CLI installed locally to generate your master key (`brew install age` or `apt install age`).

---

## Installation & Unlocking

### 1. Generate a Master Key
Generate an `age` key pair. This is the master key the CSI provider will use to encrypt and decrypt the storage backend.
```bash
age-keygen -o key.txt
cat key.txt
# Public key: age1...
# AGE-SECRET-KEY-1...
```
*Keep this key safe! If you lose it, your vault cannot be recovered.*

### 2. Deploy the CSI Provider
Apply the RBAC and DaemonSet manifests.
```bash
kubectl apply -f deploy.yaml
```
Verify the daemonset is running:
```bash
kubectl get pods -n kube-system -l app=age-vault-csi
```

### 3. Unlock the Vault via Web UI
By default, the provider starts in **Locked** mode. Pods trying to mount secrets will hang in the `ContainerCreating` state until the vault is unlocked.

Port-forward the Admin API:
```bash
kubectl port-forward -n kube-system ds/age-vault-csi 8090:8090
```
1. Open http://localhost:8090 in your browser.
2. You will see the **Vault Locked 🔒** screen.
3. Paste your `AGE-SECRET-KEY-...` into the form and click **Unlock**.

*(Note: You can also choose to mount the master key as an environment variable `MASTER_KEY` or implement the `MasterKeyProvider` interface to fetch it from a Cloud KMS automatically on boot).*

---

## Web UI User Permissions (Production)

When running in a real cluster (i.e. **not** `DEV_MODE=true`), you can enforce JWT-based access control on the Web UI. This ensures users only see, create, update, or delete secrets within the branches they are allowed to access.

### 1. Create a `perm.yaml` ConfigMap

```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: age-vault-perms
  namespace: kube-system
data:
  perm.yaml: |
    userA:
      - "/nats/*"
      - "/postgresql/*"
    userB:
      - "/app/*"
    admin:
      - userH
```

Rules:
- Each user gets a list of path patterns. Patterns support exact paths (`/db/postgres/password`) and prefix wildcards (`/nats/*`).
- The `admin` list contains usernames that have full access to **all** secrets and can perform exports.
- Only admins can click **Export Backup (.age)**.

### 2. Provide the JWT public key

The Web UI validates incoming `Authorization: Bearer <token>` headers using an RSA public key. Store it in a Secret:

```yaml
apiVersion: v1
kind: Secret
metadata:
  name: jwt-public-key
  namespace: kube-system
stringData:
  JWT_PUBLIC_KEY: |
    -----BEGIN PUBLIC KEY-----
    MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA...
    -----END PUBLIC KEY-----
```

### 3. Wire the environment variables

The DaemonSet in `deploy.yaml` already includes the volume mounts and env vars:

```yaml
env:
  - name: PERM_CONFIG_PATH
    value: /etc/age-vault/perm.yaml
  - name: JWT_PUBLIC_KEY
    valueFrom:
      secretKeyRef:
        name: jwt-public-key
        key: JWT_PUBLIC_KEY
  - name: JWT_USER_CLAIM
    value: "sub"  # default; the JWT claim to use as the username
```

When these are set, every request to the Web UI must include a valid `Authorization: Bearer <jwt>` token. The UI will then only show folders and secrets the user is allowed to read.

> **Tip:** In `DEV_MODE=true`, the permission system is **not** enforced. The Web UI remains open so you can develop and test without generating JWTs.

---

## Managing Secrets (Web UI)

Once unlocked, the Web UI at http://localhost:8090 becomes your control plane.

* **View ACLs:** See which namespaces and service accounts have access to which vault paths.
* **Blind-Write Interface:** For security, secret values cannot be read back from the UI. They are displayed as `********`.
* **Add/Update Secrets:** Use the form to insert new secrets or update existing ones. Example path: `/db/postgres/password`.
* **Offline Backups:** Admins can click **Export Backup (.age)** to download the entire vault securely. Because the export is `age`-encrypted, it is completely safe to store in version control, S3, or a local hard drive.

---

## Usage: Mounting Secrets in Pods

Now that the Vault is unlocked and populated, developers can mount secrets into their pods using a `SecretProviderClass`.

### 1. Define the SecretProviderClass
Tell the CSI driver which paths from the Vault you want to fetch:
```yaml
apiVersion: secrets-store.csi.x-k8s.io/v1
kind: SecretProviderClass
metadata:
  name: app-secrets
  namespace: production
spec:
  provider: agevault
  parameters:
    # Format: "filename_to_mount=/vault/path, next_file=/next/path"
    secrets: "db-pass=/db/postgres/password, stripe-key=/api/stripe/key"
```

### 2. Mount into a Pod
Reference the `SecretProviderClass` in your Pod's volumes:
```yaml
apiVersion: v1
kind: Pod
metadata:
  name: my-secure-app
  namespace: production
spec:
  serviceAccountName: db-client # Must match the ACL in the Vault Tree!
  containers:
  - name: app
    image: alpine
    command: ["sleep", "3600"]
    volumeMounts:
    - name: secrets-store
      mountPath: "/mnt/secrets"
      readOnly: true
  volumes:
  - name: secrets-store
    csi:
      driver: secrets-store.csi.k8s.io
      readOnly: true
      volumeAttributes:
        secretProviderClass: "app-secrets"
```

When the pod starts:
1. If the vault is locked, the Pod will wait safely in `ContainerCreating`.
2. Once unlocked, the CSI driver verifies that `production` and `db-client` are allowed to read `/db/postgres/password`.
3. If successful, the plaintext secret is mounted as a file at `/mnt/secrets/db-pass`.

## Advanced Security: Hardware Memory Wiping

This project takes advantage of the experimental `runtime/secret` package introduced in Go.

When compiled with `GOEXPERIMENT=runtimesecret` (see the `AGENTS.md`):
1. **Secure Enclave Execution:** All JSON unmarshaling, `age` decryption, and string allocation for secrets happen inside a protected `secret.Do(func(){})` context.
2. **Guaranteed Heap Wiping:** The Go Garbage Collector guarantees that the memory pages holding your plaintext secrets are **zeroed out** as soon as the gRPC mount response is sent.
3. **Template Protection:** The Web UI HTML template renderer only ever receives stripped structs. The plaintext secrets never accidentally escape onto the heap where the HTTP server could leave them lingering in memory.

This completely prevents secrets from lingering in memory space, protecting against memory dumping attacks (e.g., via compromised container host or core dumps).
