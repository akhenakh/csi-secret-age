package main

import (
	"context"
	"errors"
)

// Config represents environment configurations
type Config struct {
	MasterKey       string `env:"MASTER_KEY"` // No longer required to start up
	VaultSecretName string `env:"VAULT_SECRET_NAME" envDefault:"age-vault-backend"`
	VaultNamespace  string `env:"VAULT_NAMESPACE" envDefault:"kube-system"`
	SocketPath      string `env:"SOCKET_PATH" envDefault:"/tmp/age-vault.sock"`
	HTTPPort        int    `env:"HTTP_PORT" envDefault:"8090"`
	DevMode         bool   `env:"DEV_MODE" envDefault:"false"`

	PermConfigPath string `env:"PERM_CONFIG_PATH"`
	JWTPublicKey   string `env:"JWT_PUBLIC_KEY"`
	JWTUserClaim   string `env:"JWT_USER_CLAIM" envDefault:"sub"`

	// KMSCiphertext is the base64-encoded ciphertext blob from AWS KMS encrypt.
	// When set and compiled with the 'kms' build tag, the provider fetches the
	// age master key from AWS KMS at startup instead of using MASTER_KEY.
	KMSCiphertext string `env:"KMS_CIPHERTEXT"`

	// GCPKMSKeyName is the resource name of the GCP KMS CryptoKey used for decryption.
	// Format: projects/{project}/locations/{location}/keyRings/{keyring}/cryptoKeys/{key}
	// When set with GCPKMSCiphertext and compiled with 'gcpkms' build tag, the provider
	// fetches the age master key from GCP KMS.
	GCPKMSKeyName    string `env:"GCP_KMS_KEY_NAME"`
	GCPKMSCiphertext string `env:"GCP_KMS_CIPHERTEXT"`
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

// resolveKeyProvider is implemented in keyprovider.go with optional
// cloud provider backends registered via init() in build-tagged files.
