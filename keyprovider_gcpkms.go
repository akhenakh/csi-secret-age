//go:build gcpkms

package main

import (
	"context"
	"log/slog"

	"github.com/akhenakh/csi-secret-age/gcpkms"
)

type gcpKMSKeyProvider struct {
	ciphertext string
	client     *gcpkms.Client
}

func (p *gcpKMSKeyProvider) GetMasterKey(ctx context.Context) (string, error) {
	return p.client.GetAgeKey(ctx, p.ciphertext)
}

func init() {
	keyProviders = append(keyProviders, func(cfg *Config) MasterKeyProvider {
		if cfg.GCPKMSCiphertext == "" || cfg.GCPKMSKeyName == "" {
			return nil
		}
		gcpClient, err := gcpkms.NewClient(context.Background(), cfg.GCPKMSKeyName)
		if err != nil {
			slog.Error("Failed to create GCP KMS client, falling back to env key provider", "error", err)
			return nil
		}
		slog.Info("Using GCP KMS to fetch age master key")
		return &gcpKMSKeyProvider{ciphertext: cfg.GCPKMSCiphertext, client: gcpClient}
	})
}
