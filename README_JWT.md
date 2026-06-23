csi-secret-age supports two configurations to validate users authentication, JWKS or against a public JWT key.


# JWKS Configuration

If your identity provider rotates signing keys, configure a JSON Web Key Set
(JWKS) instead of a static public key. The provider fetches the key set,
caches it, and selects the correct RSA key using the token's `kid` header.

Set **exactly one** of the following (mutually exclusive with
`JWT_PUBLIC_KEY`/`JWT_PUBLIC_KEY_FILE`):

| Environment Variable | File Variant | Purpose |
|---|---|---|
| `JWT_JWKS_URL` | — | URL returning JWKS JSON |
| `JWT_JWKS` | `JWT_JWKS_FILE` | Inline or file-based JWKS JSON |

Use `JWT_JWKS_REFRESH_INTERVAL` to control the cache TTL (default `15m`; set to
`0` to fetch on every validation).

Example using a JWKS URL:

```yaml
env:
  - name: JWT_JWKS_URL
    value: "https://auth.example.com/.well-known/jwks.json"
  - name: JWT_JWKS_REFRESH_INTERVAL
    value: "15m"
  - name: JWT_USER_CLAIM
    value: "sub"
```

Tokens validated via JWKS **must include a `kid` header**.

## 4. Use the Token

Include the signed JWT as a Bearer token in requests to the Web UI:

```bash
curl -H "Authorization: Bearer $(cat /tmp/admin.jwt)" http://localhost:8090/entry?path=/db/postgres/password
```

## Key Requirements Summary

| Requirement | Value |
|-------------|-------|
| Key algorithm | RSA, 2048-bit minimum |
| Signing algorithm | RS256 (SHA-256) |
| Public key format | PEM-encoded PKIX (`-----BEGIN PUBLIC KEY-----`) or JWKS RSA keys |
| JWT claim for username | `sub` (configurable via `JWT_USER_CLAIM`) |
| JWKS token requirement | Token header must include `kid` |
| JWKS cache TTL | `JWT_JWKS_REFRESH_INTERVAL` (default `15m`) |

# JWT Key Generation for the Web UI

The Web UI uses RSA-signed JWTs (RS256) for authentication. You need an RSA key pair — a private key for signing tokens and a public key to give the CSI provider for validation.

## 1. Generate an RSA Key Pair

```bash
# Generate a 2048-bit RSA private key
openssl genpkey -algorithm RSA -out jwt-private.pem -pkeyopt rsa_keygen_bits:2048

# Extract the public key in PKIX/PEM format (required by the provider)
openssl pkey -in jwt-private.pem -pubout -out jwt-public.pem
```

The public key file (`jwt-public.pem`) will look like:

```
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA...
-----END PUBLIC KEY-----
```

## 2. Sign a JWT Token

Here's a minimal Go example that creates a JWT for user `alice`:

```go
package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

func main() {
	// Read the private key
	pemBytes, _ := os.ReadFile("jwt-private.pem")
	block, _ := pem.Decode(pemBytes)
	privateKey, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		panic(err)
	}

	// Create a token with claims
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
		"sub":  "alice",                                 // username (matches perm.yaml entry)
		"iat":  time.Now().Unix(),                        // issued at
		"exp":  time.Now().Add(24 * time.Hour).Unix(),    // expires in 24h
	})

	// Sign it
	signed, err := token.SignedString(privateKey.(*rsa.PrivateKey))
	if err != nil {
		panic(err)
	}

	fmt.Println(signed)
}
```

Or with a one-liner using a small helper script:

```bash
# Build and run the signer
go run jwt-sign.go --key jwt-private.pem --user alice
```

### Using only the CLI

If you prefer not to write Go code, you can use `openssl` + `jq` to construct and sign a JWT:

```bash
# Create header and payload, then sign with RS256
HEADER=$(echo -n '{"alg":"RS256","typ":"JWT"}' | base64 -w0 | tr '+/' '-_' | tr -d '=')
PAYLOAD=$(echo -n '{"sub":"alice","iat":'"$(date +%s)"',"exp":'"$(date -d '+24 hours' +%s)"'}' | base64 -w0 | tr '+/' '-_' | tr -d '=')
SIGNATURE=$(echo -n "$HEADER.$PAYLOAD" | openssl dgst -sha256 -sign jwt-private.pem -binary | base64 -w0 | tr '+/' '-_' | tr -d '=')
echo "$HEADER.$PAYLOAD.$SIGNATURE"
```

## 3. Provide the Public Key to the Provider

Store the public key in a Kubernetes Secret and reference it in the DaemonSet:

```yaml
apiVersion: v1
kind: Secret
metadata:
  name: jwt-public-key
  namespace: kube-system
stringData:
  # The key name becomes the filename inside the mounted volume
  jwt-public-key.pem: |
    -----BEGIN PUBLIC KEY-----
    MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA...
    -----END PUBLIC KEY-----
```

This matches the DaemonSet mount — the Secret is mounted at `/etc/csi-secret-age/secrets/jwt/`, so each key becomes a file (e.g. `jwt-public-key.pem`). The env var `JWT_PUBLIC_KEY_FILE` then points to the full path:

Then wire it via env in `deploy.yaml`:

```yaml
env:
  - name: JWT_PUBLIC_KEY_FILE
    value: /etc/csi-secret-age/secrets/jwt/public-key.pem
  - name: JWT_USER_CLAIM
    value: "sub"    # default; the JWT claim used as the username
```

