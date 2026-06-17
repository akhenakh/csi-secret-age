package main

var keyProviders []func(*Config) MasterKeyProvider

func resolveKeyProvider(cfg *Config) MasterKeyProvider {
	for _, p := range keyProviders {
		if prov := p(cfg); prov != nil {
			return prov
		}
	}
	return &EnvKeyProvider{Key: cfg.MasterKey}
}
