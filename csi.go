package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"runtime/secret"
	"strings"

	"sigs.k8s.io/secrets-store-csi-driver/provider/v1alpha1"
)

type ProviderServer struct {
	v1alpha1.UnimplementedCSIDriverProviderServer
	manager *VaultManager
	logger  *slog.Logger
}

func (s *ProviderServer) Mount(ctx context.Context, req *v1alpha1.MountRequest) (*v1alpha1.MountResponse, error) {
	if s.manager.IsLocked() {
		s.logger.Warn("Mount requested but Vault is locked")
		return nil, ErrVaultLocked
	}

	var attrs map[string]string
	if err := json.Unmarshal([]byte(req.GetAttributes()), &attrs); err != nil {
		return nil, fmt.Errorf("failed to unmarshal attributes: %w", err)
	}

	podNamespace := strings.TrimSpace(attrs["csi.storage.k8s.io/pod.namespace"])
	podSA := strings.TrimSpace(attrs["csi.storage.k8s.io/serviceAccount.name"])
	requestedSecretsStr := attrs["secrets"]

	if podNamespace == "" || podSA == "" {
		return nil, fmt.Errorf("pod namespace and service account are required")
	}
	if strings.ContainsAny(podNamespace, "/\\\x00") || strings.ContainsAny(podSA, "/\\\x00") {
		return nil, fmt.Errorf("invalid pod identity: namespace or service account contains forbidden characters")
	}

	s.logger.Info("Mount request", "podNS", podNamespace, "podSA", podSA)

	var files []*v1alpha1.File
	var versions []*v1alpha1.ObjectVersion
	var mountErr error

	// 🔒 Secure Execution Context
	secret.Do(func() {
		tree, err := s.manager.LoadAndDecrypt(ctx)
		if err != nil {
			mountErr = fmt.Errorf("failed to load vault: %w", err)
			return
		}

		requests := strings.Split(requestedSecretsStr, ",")
		for _, reqPair := range requests {
			reqPair = strings.TrimSpace(reqPair)
			if reqPair == "" {
				continue
			}

			parts := strings.SplitN(reqPair, "=", 2)
			if len(parts) != 2 {
				continue
			}
			fileName := strings.TrimSpace(parts[0])
			vaultPath := strings.TrimSpace(parts[1])

			if strings.Contains(fileName, "/") || strings.Contains(fileName, "\\") || fileName == ".." || strings.HasPrefix(fileName, ".") {
				mountErr = fmt.Errorf("invalid file name %q", fileName)
				return
			}

			node, exists := tree.Nodes[vaultPath]
			if !exists {
				mountErr = fmt.Errorf("secret path %s not found in vault", vaultPath)
				return
			}

			if !node.CanAccess(podNamespace, podSA) {
				s.logger.Warn("Access denied", "path", vaultPath, "namespace", podNamespace, "sa", podSA)
				mountErr = fmt.Errorf("access denied to path %s", vaultPath)
				return
			}

			files = append(files, &v1alpha1.File{
				Path:     fileName,
				Mode:     0644,
				Contents: []byte(node.Value),
			})
			versions = append(versions, &v1alpha1.ObjectVersion{
				Id:      fileName,
				Version: "latest",
			})
		}
	})

	if mountErr != nil {
		return nil, mountErr
	}

	return &v1alpha1.MountResponse{
		Files:         files,
		ObjectVersion: versions,
	}, nil
}

func (s *ProviderServer) Version(ctx context.Context, req *v1alpha1.VersionRequest) (*v1alpha1.VersionResponse, error) {
	return &v1alpha1.VersionResponse{
		Version:        "v1alpha1",
		RuntimeName:    "age-vault-provider",
		RuntimeVersion: "1.0.0",
	}, nil
}
