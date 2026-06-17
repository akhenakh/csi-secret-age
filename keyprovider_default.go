//go:build !kms

package main

func resolveKeyProvider(cfg *Config) MasterKeyProvider {
	return &EnvKeyProvider{Key: cfg.MasterKey}
}
