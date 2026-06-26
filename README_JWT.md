# JWT Authentication for the Web UI

The Web UI validates incoming `Authorization: Bearer <token>` headers. Tokens must be **RS256-signed RSA JWTs**. The provider supports two ways to obtain the validation key:

- A static PEM-encoded RSA public key (`JWT_PUBLIC_KEY` / `JWT_PUBLIC_KEY_FILE`).
- A JSON Web Key Set (`JWT_JWKS_URL`, or `JWT_JWKS` / `JWT_JWKS_FILE`).

These two approaches are **mutually exclusive** — configure one or the other.

---

## Static Public Key

### 1. Generate an RSA Key Pair

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

### 2. Sign a JWT Token

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
		"sub":  "alice",                                // username (matches perm.yaml entry)
		"iat":  time.Now().Unix(),                      // issued at
		"exp":  time.Now().Add(24 * time.Hour).Unix(),  // expires in 24h
		// Optional, but required when JWT_AUDIENCE / JWT_ISSUER are configured:
		// "aud":  "387398432539-xxx.apps.googleusercontent.com",
		// "iss":  "https://accounts.google.com",
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

### 3. Provide the Public Key to the Provider

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

This matches the DaemonSet mount — the Secret is mounted at `/etc/csi-secret-age/secrets/jwt/`, so each key becomes a file (e.g. `jwt-public-key.pem`). The env var `JWT_PUBLIC_KEY_FILE` then points to the full path.

Wire it via env in `deploy.yaml`:

```yaml
env:
  - name: JWT_PUBLIC_KEY_FILE
    value: /etc/csi-secret-age/secrets/jwt/public-key.pem
  - name: JWT_USER_CLAIM
    value: "sub"    # default; the JWT claim used as the username
```

---

## JWKS Configuration

If your identity provider rotates signing keys, configure a JSON Web Key Set
(JWKS) instead of a static public key. The provider fetches the key set,
caches it, and selects the correct RSA key using the token's `kid` header.

Set **exactly one** of the following:

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

---

## SSO: Audience & Issuer Validation

When using an external identity provider such as Google, validating the
signature is not enough. You must also verify that the token was issued for
your application by checking the **`aud`** claim (your OAuth `client_id`) and,
optionally, the **`iss`** claim.

Set `JWT_AUDIENCE` to your client ID and `JWT_ISSUER` to the expected issuer:

```yaml
env:
  - name: JWT_JWKS_URL
    value: "https://www.googleapis.com/oauth2/v3/certs"
  - name: JWT_AUDIENCE
    value: "387398432539-xxx.apps.googleusercontent.com"
  - name: JWT_ISSUER
    value: "https://accounts.google.com"
  - name: JWT_USER_CLAIM
    value: "email"
```

Tokens that do not match the configured audience or issuer will be rejected
with a 401 Unauthorized response.

---

## OIDC Access Tokens via UserInfo (Envoy Gateway OIDC — recommended for browsers)

Browser SSO with Envoy Gateway OIDC is the common case, but the gateway does
**not** hand a self-contained ID token (JWT) to the upstream — the ID token lives
in an *encrypted* session cookie, and current Envoy versions cannot forward it as
a header. What the gateway *can* forward (`forwardAccessToken: true`) is the
OAuth2 **access token**, which for Google is *opaque* (not a JWT) and so cannot be
verified locally.

To handle this, `csi-secret-age` resolves an opaque `Authorization: Bearer`
access token by calling the provider's **UserInfo endpoint**, which it discovers
automatically from `JWT_ISSUER` (`{issuer}/.well-known/openid-configuration`).
This is **provider-agnostic** — Google, Azure AD, Okta, Keycloak, Auth0, etc.

```yaml
env:
  - name: JWT_ISSUER
    value: "https://accounts.google.com"
  - name: JWT_USER_CLAIM
    value: "email"
  # How long a resolved identity is cached (avoids a UserInfo round-trip per
  # request). Defaults to 5m.
  - name: OAUTH_USERINFO_CACHE_TTL
    value: "5m"
  # Do NOT set JWT_USER_HEADER — this path needs no trusted header.
```

UserInfo validation is enabled automatically when `JWT_ISSUER` is set and OIDC
discovery succeeds (discovery failure is non-fatal and logged). The resolved
`email` (or whichever `JWT_USER_CLAIM` you choose) is looked up in `perm.yaml`.
When the claim is `email`, an explicit `email_verified: false` from the provider
is rejected.

### Gateway side

Configure the Envoy Gateway `SecurityPolicy` to authenticate at the gateway and
forward the access token (see `deploy.yaml` for a full example):

```yaml
apiVersion: gateway.envoyproxy.io/v1alpha1
kind: SecurityPolicy
metadata:
  name: csi-secret-age-google-oidc
  namespace: kube-system
spec:
  targetRefs:
    - group: gateway.networking.k8s.io
      kind: HTTPRoute
      name: csi-secret-age-admin
  oidc:
    provider:
      issuer: "https://accounts.google.com"
    clientID: "387398432539-xxx.apps.googleusercontent.com"
    clientSecret:
      name: "csi-secret-age-google-oidc-secret"   # must hold key "client-secret"
    scopes: ["email"]                              # else Google omits the email claim
    redirectURL: "https://vault.example.com/oauth2/callback"  # register in the Google OAuth client
    forwardAccessToken: true
```

> **Security note — no audience binding.** The UserInfo endpoint returns the
> token's *user* claims but **not** its audience (`aud`), so this path cannot bind
> the token to a specific client. It establishes *who* the caller is; the
> permissions file is the authorization gate (a token minted for another client
> of the same issuer resolves to that user's own email, and therefore only that
> user's own permissions). If you need strict audience binding, use the
> self-contained-JWT path above (CLI clients sending `Authorization: Bearer <id_token>`),
> which validates `aud`/`iss`/signature locally.

You can run both paths at once: opaque access tokens go through UserInfo, while
self-contained JWTs are validated (and audience-bound) by the JWKS/public-key
path.

---

## Trusted Header Authentication (legacy proxy integration)

> **Prefer the UserInfo path above.** Header trust requires the proxy to
> perfectly strip/overwrite the header for *all* untrusted traffic; a single
> misconfiguration lets anyone with direct network access impersonate any user.
> The UserInfo path has no such trusted-header surface.

Some ingress/proxy implementations authenticate the user at the proxy layer and inject the identity as a plain HTTP header (e.g. an OIDC proxy that sets `X-Forwarded-User`).

To support this deployment model, `csi-secret-age` can fall back to a trusted HTTP header for the username when no valid JWT Bearer token is present:

```yaml
env:
  - name: JWT_USER_HEADER
    value: "X-Forwarded-User"
  # Optional: force admin status based on another header value
  - name: JWT_ADMIN_HEADER
    value: "X-Forwarded-Groups"
  - name: JWT_ADMIN_VALUE
    value: "admins"
```

When `JWT_USER_HEADER` is set:

1. If the request has a valid `Authorization: Bearer <jwt>` token, it is used as usual (JWT takes precedence).
2. Otherwise, the value of `JWT_USER_HEADER` is read as the authenticated username and looked up in the permissions file.
3. If `JWT_ADMIN_HEADER` and `JWT_ADMIN_VALUE` are also set and the header matches, the user is treated as an admin regardless of the permissions file.

You do **not** need to configure `JWT_PUBLIC_KEY` or a JWKS if you only use header-based authentication. If you configure both, JWT is preferred and the header is a fallback.

**Important security note:** the proxy must strip or overwrite these headers for untrusted traffic. Anyone able to send requests directly to `csi-secret-age` with the configured header can impersonate a user.

## Using the Token

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
| Audience validation | `JWT_AUDIENCE` (e.g. your OAuth `client_id`) |
| Issuer validation / OIDC discovery | `JWT_ISSUER` (e.g. `https://accounts.google.com`) |
| Opaque access-token validation | OIDC UserInfo, enabled when `JWT_ISSUER` is set |
| UserInfo identity cache TTL | `OAUTH_USERINFO_CACHE_TTL` (default `5m`) |
