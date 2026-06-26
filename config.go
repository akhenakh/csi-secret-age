package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"
)

// Config represents environment configurations.
// Secret fields support a _FILE suffix (e.g. MASTER_KEY_FILE) to read the
// value from a file instead of an environment variable. When both the inline
// and file variants are set, the file takes precedence.
type Config struct {
	// MasterKey is the age identity (secret key) used to encrypt/decrypt the vault.
	// Not required at startup; the vault can be unlocked later via the Web UI.
	// Use MasterKeyFile to read from a file instead.
	MasterKey     string `env:"MASTER_KEY"`
	MasterKeyFile string `env:"MASTER_KEY_FILE"`

	VaultSecretName string `env:"VAULT_SECRET_NAME" envDefault:"csi-secret-age-backend"`
	VaultNamespace  string `env:"VAULT_NAMESPACE" envDefault:"kube-system"`
	SocketPath      string `env:"SOCKET_PATH" envDefault:"/tmp/csi-secret-age.sock"`
	HTTPPort        int    `env:"HTTP_PORT" envDefault:"8090"`
	DevMode         bool   `env:"DEV_MODE" envDefault:"false"`
	LogLevel        string `env:"LOG_LEVEL" envDefault:"INFO"`

	PermConfigPath string `env:"PERM_CONFIG_PATH"`
	// JWTPublicKey is the PEM-encoded RSA public key used to validate JWT tokens
	// for the permission system. Use JWTPublicKeyFile to read from a file instead.
	// Mutually exclusive with JWT_JWKS_URL / JWT_JWKS / JWT_JWKS_FILE.
	JWTPublicKey     string `env:"JWT_PUBLIC_KEY"`
	JWTPublicKeyFile string `env:"JWT_PUBLIC_KEY_FILE"`
	JWTUserClaim     string `env:"JWT_USER_CLAIM" envDefault:"sub"`
	// JWTAudience is the expected audience (aud) claim of incoming JWTs.
	// For Google SSO this is your OAuth client_id. When set, every token must
	// contain this audience or it will be rejected.
	JWTAudience string `env:"JWT_AUDIENCE"`
	// JWTIssuer is the expected issuer (iss) claim of incoming JWTs.
	// For Google SSO this is typically "https://accounts.google.com".
	JWTIssuer string `env:"JWT_ISSUER"`

	// JWTUserHeader enables header-based authentication as a fallback when a
	// valid JWT Bearer token is not present. The value of this HTTP header is
	// treated as the authenticated username and looked up in the permissions
	// file. This is intended for deployments where an upstream proxy (e.g.
	// Envoy Gateway OIDC) has already authenticated the user and injects the
	// identity via a trusted header. The proxy MUST strip or overwrite this
	// header for untrusted requests.
	JWTUserHeader string `env:"JWT_USER_HEADER"`
	// JWTAdminHeader, when set with JWTAdminValue, marks the request as admin
	// if the header value matches. If unset, admin status is resolved from the
	// permissions file as usual.
	JWTAdminHeader string `env:"JWT_ADMIN_HEADER"`
	JWTAdminValue  string `env:"JWT_ADMIN_VALUE"`

	// JWT_JWKS_URL fetches a JSON Web Key Set from an HTTPS (or HTTP) URL.
	// The key identified by the token's `kid` header is used for RS256 validation.
	// Mutually exclusive with JWT_PUBLIC_KEY / JWT_JWKS / JWT_JWKS_FILE.
	JWTJWKSURL string `env:"JWT_JWKS_URL"`
	// JWTJWKS is an inline JSON Web Key Set. Use JWT_JWKS_FILE to read from a file.
	JWTJWKS     string `env:"JWT_JWKS"`
	JWTJWKSFile string `env:"JWT_JWKS_FILE"`
	// JWTJWKSRefreshInterval controls how often the JWKS URL cache is refreshed.
	JWTJWKSRefreshInterval time.Duration `env:"JWT_JWKS_REFRESH_INTERVAL" envDefault:"15m"`

	// OAuthUserInfoCacheTTL controls how long an identity resolved from the OIDC
	// UserInfo endpoint is cached. UserInfo validation is enabled automatically
	// when JWT_ISSUER is set and OIDC discovery succeeds, and is used to validate
	// opaque OAuth2 access tokens (e.g. those forwarded by a gateway after an OIDC
	// login) that are not self-contained JWTs.
	OAuthUserInfoCacheTTL time.Duration `env:"OAUTH_USERINFO_CACHE_TTL" envDefault:"5m"`

	// KMSCiphertext is the base64-encoded ciphertext blob from AWS KMS encrypt.
	// When set and compiled with the 'kms' build tag, the provider fetches the
	// age master key from AWS KMS at startup instead of using MASTER_KEY.
	// Use KMSCiphertextFile to read from a file instead.
	KMSCiphertext     string `env:"KMS_CIPHERTEXT"`
	KMSCiphertextFile string `env:"KMS_CIPHERTEXT_FILE"`

	// GCPKMSKeyName is the resource name of the GCP KMS CryptoKey used for decryption.
	// Format: projects/{project}/locations/{location}/keyRings/{keyring}/cryptoKeys/{key}
	// When set with GCPKMSCiphertext and compiled with 'gcpkms' build tag, the provider
	// fetches the age master key from GCP KMS. Use GCPKMSKeyNameFile to read from a file.
	GCPKMSKeyName     string `env:"GCP_KMS_KEY_NAME"`
	GCPKMSKeyNameFile string `env:"GCP_KMS_KEY_NAME_FILE"`
	// GCPKMSCiphertext is the base64-encoded ciphertext blob from GCP KMS encrypt.
	// Use GCPKMSCiphertextFile to read from a file instead.
	GCPKMSCiphertext     string `env:"GCP_KMS_CIPHERTEXT"`
	GCPKMSCiphertextFile string `env:"GCP_KMS_CIPHERTEXT_FILE"`
}

// MasterKeyProvider defines an interface for fetching the master age key
// from external safe encryption providers (AWS KMS, GCP KMS, HashiCorp Vault, etc.)
type MasterKeyProvider interface {
	GetMasterKey(ctx context.Context) (string, error)
}

// EnvKeyProvider is a simple provider that uses the local environment variable.
type EnvKeyProvider struct {
	Key string
}

func (e *EnvKeyProvider) GetMasterKey(ctx context.Context) (string, error) {
	if e.Key == "" {
		return "", errors.New("master key not found in environment")
	}
	return e.Key, nil
}

// resolveSecretValue reads a secret from a file if filePath is set, otherwise
// falls back to the inline value. File content is trimmed of leading/trailing
// whitespace. File takes precedence over the inline value when both are set.
func resolveSecretValue(inline, filePath string) (string, error) {
	if filePath != "" {
		data, err := os.ReadFile(filePath)
		if err != nil {
			return "", fmt.Errorf("failed to read secret file %q: %w", filePath, err)
		}
		return strings.TrimSpace(string(data)), nil
	}
	return inline, nil
}

// ResolveSecrets resolves file-backed secret values, preferring files over
// inline environment values. Call this after env.Parse.
func (c *Config) ResolveSecrets() error {
	resolvers := []struct {
		name     string
		inline   *string
		filePath string
	}{
		{"MASTER_KEY", &c.MasterKey, c.MasterKeyFile},
		{"JWT_PUBLIC_KEY", &c.JWTPublicKey, c.JWTPublicKeyFile},
		{"JWT_JWKS", &c.JWTJWKS, c.JWTJWKSFile},
		{"KMS_CIPHERTEXT", &c.KMSCiphertext, c.KMSCiphertextFile},
		{"GCP_KMS_KEY_NAME", &c.GCPKMSKeyName, c.GCPKMSKeyNameFile},
		{"GCP_KMS_CIPHERTEXT", &c.GCPKMSCiphertext, c.GCPKMSCiphertextFile},
	}
	for _, r := range resolvers {
		val, err := resolveSecretValue(*r.inline, r.filePath)
		if err != nil {
			return fmt.Errorf("%s: %w", r.name, err)
		}
		*r.inline = val
	}
	return nil
}

// resolveKeyProvider is implemented in keyprovider.go with optional
// cloud provider backends registered via init() in build-tagged files.
