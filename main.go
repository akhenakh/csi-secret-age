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
	"syscall"

	"github.com/caarlos0/env/v11"
	"golang.org/x/sync/errgroup"
	"google.golang.org/grpc"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"runtime/secret"
	"sigs.k8s.io/secrets-store-csi-driver/provider/v1alpha1"
)

func main() {
	var cfg Config
	if err := env.Parse(&cfg); err != nil {
		fmt.Printf("failed to parse config: %+v\n", err)
		os.Exit(1)
	}

	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))

	if secret.Enabled() {
		logger.Info("runtime/secret experiment is enabled. Memory wiping active.")
	} else {
		logger.Warn("runtime/secret experiment is NOT enabled. Plaintext secrets may linger in heap memory.")
	}

	k8sConfig, err := rest.InClusterConfig()
	if err != nil {
		logger.Error("Failed to get in-cluster config", "error", err)
		os.Exit(1)
	}
	k8sClient, err := kubernetes.NewForConfig(k8sConfig)
	if err != nil {
		logger.Error("Failed to create k8s client", "error", err)
		os.Exit(1)
	}

	// You can easily swap this out with an AWSKMSProvider or GCPKMSProvider implementation in the future.
	keyProvider := &EnvKeyProvider{Key: cfg.MasterKey}
	manager := NewVaultManager(cfg, k8sClient, keyProvider)

	if manager.IsLocked() {
		logger.Warn("Starting in LOCKED mode. Access the Web UI to unlock the vault.")
	} else {
		logger.Info("Started successfully in UNLOCKED mode via environment Master Key.")
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	g, ctx := errgroup.WithContext(ctx)

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
		os.Chmod(cfg.SocketPath, 0777)

		grpcServer := grpc.NewServer()
		v1alpha1.RegisterCSIDriverProviderServer(grpcServer, &ProviderServer{manager: manager, logger: logger})

		logger.Info("gRPC Provider listening", "socket", cfg.SocketPath)
		go func() { <-ctx.Done(); grpcServer.GracefulStop() }()
		return grpcServer.Serve(lis)
	})

	// 2. HTTP Admin Server
	g.Go(func() error {
		return startHTTPServer(ctx, logger, cfg, manager)
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
