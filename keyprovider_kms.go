//go:build kms

package main

import (
	"context"
	"log/slog"

	awskms "github.com/akhenakh/csi-secret-age/awskms"
)

type awsKMSKeyProvider struct {
	ciphertext string
	client     *awskms.Client
}

func (p *awsKMSKeyProvider) GetMasterKey(ctx context.Context) (string, error) {
	return p.client.GetAgeKey(ctx, p.ciphertext)
}

func init() {
	keyProviders = append(keyProviders, func(cfg *Config) MasterKeyProvider {
		if cfg.KMSCiphertext == "" {
			return nil
		}
		awsClient, err := awskms.NewClient(context.Background())
		if err != nil {
			slog.Error("Failed to create AWS KMS client, falling back to env key provider", "error", err)
			return nil
		}
		slog.Info("Using AWS KMS to fetch age master key")
		return &awsKMSKeyProvider{ciphertext: cfg.KMSCiphertext, client: awsClient}
	})
}
