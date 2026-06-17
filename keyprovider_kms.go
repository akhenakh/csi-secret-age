//go:build kms

package main

import (
	"context"
	"log/slog"

	"github.com/akhenakh/csi-secret-age/kms"
)

type kmsKeyProvider struct {
	ciphertext string
	client     *kms.Client
}

func (p *kmsKeyProvider) GetMasterKey(ctx context.Context) (string, error) {
	return p.client.GetAgeKey(ctx, p.ciphertext)
}

func resolveKeyProvider(cfg *Config) MasterKeyProvider {
	if cfg.KMSCiphertext != "" {
		kmsClient, err := kms.NewClient(context.Background())
		if err != nil {
			slog.Error("Failed to create AWS KMS client, falling back to env key provider", "error", err)
			return &EnvKeyProvider{Key: cfg.MasterKey}
		}
		slog.Info("Using AWS KMS to fetch age master key")
		return &kmsKeyProvider{ciphertext: cfg.KMSCiphertext, client: kmsClient}
	}
	return &EnvKeyProvider{Key: cfg.MasterKey}
}
