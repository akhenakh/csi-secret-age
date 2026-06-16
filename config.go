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

// TODO: Implement Cloud Providers here (e.g. AWSKMSProvider, GCPKMSProvider)
// func (a *AWSKMSProvider) GetMasterKey(ctx context.Context) (string, error) { ... }
