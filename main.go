package main

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"filippo.io/age"
	"github.com/caarlos0/env/v11"
	"golang.org/x/sync/errgroup"
	"google.golang.org/grpc"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/fake"
	"k8s.io/client-go/rest"
	"runtime/secret"
	"sigs.k8s.io/secrets-store-csi-driver/provider/v1alpha1"
)

// slogLevel parses a log-level string into a slog.Level.
func slogLevel(level string) (slog.Level, error) {
	switch strings.ToUpper(level) {
	case "DEBUG":
		return slog.LevelDebug, nil
	case "INFO":
		return slog.LevelInfo, nil
	case "WARN", "WARNING":
		return slog.LevelWarn, nil
	case "ERROR":
		return slog.LevelError, nil
	default:
		return slog.LevelInfo, fmt.Errorf("unknown log level %q", level)
	}
}

func main() {
	var cfg Config
	if err := env.Parse(&cfg); err != nil {
		fmt.Printf("failed to parse config: %+v\n", err)
		os.Exit(1)
	}
	if err := cfg.ResolveSecrets(); err != nil {
		fmt.Printf("failed to resolve secrets: %+v\n", err)
		os.Exit(1)
	}

	level, err := slogLevel(cfg.LogLevel)
	if err != nil {
		fmt.Printf("invalid LOG_LEVEL: %v\n", err)
		os.Exit(1)
	}
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: level}))

	// secret.Enabled() only reports true while Do is on the call stack, so it
	// must be probed from inside Do. A direct call from main always returns
	// false even when the experiment is compiled in and active.
	var memoryWipingActive bool
	secret.Do(func() {
		memoryWipingActive = secret.Enabled()
	})
	if memoryWipingActive {
		logger.Info("runtime/secret active: temporary secret memory will be wiped.")
	} else {
		logger.Warn("runtime/secret NOT active (experiment disabled or unsupported platform). Plaintext secrets may linger in heap memory.")
	}

	var k8sClient kubernetes.Interface
	if cfg.DevMode {
		logger.Warn("DEV MODE enabled: using fake Kubernetes client and auto-generated master key")
		k8sClient = fake.NewSimpleClientset()
	} else {
		k8sConfig, err := rest.InClusterConfig()
		if err != nil {
			logger.Error("Failed to get in-cluster config", "error", err)
			os.Exit(1)
		}
		var errClient error
		k8sClient, errClient = kubernetes.NewForConfig(k8sConfig)
		if errClient != nil {
			logger.Error("Failed to create k8s client", "error", errClient)
			os.Exit(1)
		}
	}

	// Auto-generate a throwaway key in dev mode so the vault is immediately usable
	if cfg.DevMode && cfg.MasterKey == "" && cfg.KMSCiphertext == "" && cfg.GCPKMSCiphertext == "" {
		identity, err := age.GenerateX25519Identity()
		if err != nil {
			logger.Error("Failed to generate dev mode master key", "error", err)
			os.Exit(1)
		}
		cfg.MasterKey = identity.String()
		logger.Info("Dev mode auto-generated master key", "key", cfg.MasterKey)
	}

	keyProvider := resolveKeyProvider(&cfg)
	manager := NewVaultManager(cfg, k8sClient, keyProvider)

	var permMgr *PermissionManager
	if cfg.PermConfigPath != "" {
		var errPerm error
		permMgr, errPerm = NewPermissionManagerWithJWTConfig(cfg.PermConfigPath, JWTKeyConfig{
			PublicKeyPEM:    cfg.JWTPublicKey,
			JWKSURL:         cfg.JWTJWKSURL,
			JWKSJSON:        cfg.JWTJWKS,
			RefreshInterval: cfg.JWTJWKSRefreshInterval,
			Audience:        cfg.JWTAudience,
			Issuer:          cfg.JWTIssuer,
		}, cfg.JWTUserClaim)
		if errPerm != nil {
			logger.Error("Failed to load permissions", "error", errPerm)
			os.Exit(1)
		}
		logger.Info("Permissions loaded", "path", cfg.PermConfigPath, "user_claim", cfg.JWTUserClaim)

		// When an issuer is configured, run OIDC discovery so opaque OAuth2 access
		// tokens (e.g. forwarded by the gateway after an OIDC login) can be
		// validated against the provider's UserInfo endpoint. Discovery failure is
		// non-fatal: the JWT and header auth paths still work without it.
		if cfg.JWTIssuer != "" {
			discoveryCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			provider, errOIDC := NewOIDCProvider(discoveryCtx, cfg.JWTIssuer)
			cancel()
			if errOIDC != nil {
				logger.Warn("OIDC discovery failed; opaque access-token (UserInfo) validation disabled",
					"issuer", cfg.JWTIssuer, "error", errOIDC)
			} else {
				permMgr.EnableUserInfoAuth(provider, cfg.OAuthUserInfoCacheTTL)
				logger.Info("OIDC UserInfo access-token validation enabled",
					"issuer", cfg.JWTIssuer, "cache_ttl", cfg.OAuthUserInfoCacheTTL)
			}
		}

		if cfg.JWTUserHeader != "" {
			logger.Warn("Header-based authentication enabled: trusting upstream proxy to set header",
				"user_header", cfg.JWTUserHeader,
				"admin_header", cfg.JWTAdminHeader,
				"admin_value", cfg.JWTAdminValue,
			)
		}
	}

	if manager.IsLocked() {
		logger.Warn("Starting in LOCKED mode. Access the Web UI to unlock the vault.")
	} else {
		logger.Info("Started successfully in UNLOCKED mode via environment Master Key.")
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	g, ctx := errgroup.WithContext(ctx)

	// 0. Permissions file watcher
	if permMgr != nil {
		g.Go(func() error {
			return permMgr.Watch(ctx, logger)
		})
	}

	// 1. gRPC CSI Server
	g.Go(func() error {
		if err := os.Remove(cfg.SocketPath); err != nil && !os.IsNotExist(err) {
			return err
		}
		if err := os.MkdirAll(filepath.Dir(cfg.SocketPath), 0755); err != nil {
			return err
		}
		lis, err := net.Listen("unix", cfg.SocketPath)
		if err != nil {
			return err
		}
		os.Chmod(cfg.SocketPath, 0700)

		grpcServer := grpc.NewServer()
		v1alpha1.RegisterCSIDriverProviderServer(grpcServer, &ProviderServer{manager: manager, permMgr: permMgr, logger: logger})

		logger.Info("gRPC Provider listening", "socket", cfg.SocketPath)
		go func() { <-ctx.Done(); grpcServer.GracefulStop() }()
		return grpcServer.Serve(lis)
	})

	// 2. HTTP Admin Server
	g.Go(func() error {
		return startHTTPServer(ctx, logger, cfg, manager, permMgr)
	})

	interrupt := make(chan os.Signal, 1)
	signal.Notify(interrupt, syscall.SIGINT, syscall.SIGTERM)

	select {
	case <-interrupt:
		logger.Info("Shutting down")
		cancel()
	case <-ctx.Done():
	}

	if err := g.Wait(); err != nil && err != context.Canceled && err != http.ErrServerClosed {
		logger.Error("Server error", "error", err)
		os.Exit(1)
	}
}
