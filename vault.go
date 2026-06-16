package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"runtime/secret"
	"strings"
	"sync"
	"time"

	"filippo.io/age"
	corev1 "k8s.io/api/core/v1"
	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

type VaultNode struct {
	Value                  string   `json:"value"`
	IsFolder               bool     `json:"isFolder"`
	AllowedNamespaces      []string `json:"allowedNamespaces"`
	AllowedServiceAccounts []string `json:"allowedServiceAccounts"`
}

func (n *VaultNode) CanAccess(namespace, sa string) bool {
	nsMatch := len(n.AllowedNamespaces) == 0
	for _, allowed := range n.AllowedNamespaces {
		if allowed == namespace || allowed == "*" {
			nsMatch = true
			break
		}
	}
	saMatch := len(n.AllowedServiceAccounts) == 0
	for _, allowed := range n.AllowedServiceAccounts {
		if allowed == sa || allowed == "*" {
			saMatch = true
			break
		}
	}
	return nsMatch && saMatch
}

type VaultTree struct {
	Nodes map[string]*VaultNode `json:"nodes"`
}

var ErrVaultLocked = errors.New("Vault is currently locked. Master key is required.")

type VaultManager struct {
	k8sClient kubernetes.Interface
	config    Config

	mu       sync.RWMutex
	identity *age.X25519Identity
	isLocked bool
}

func NewVaultManager(cfg Config, client kubernetes.Interface, keyProvider MasterKeyProvider) *VaultManager {
	vm := &VaultManager{
		k8sClient: client,
		config:    cfg,
		isLocked:  true, // Start locked by default
	}

	// Try to auto-unlock if the key provider has the key (e.g. env var or Cloud KMS)
	if keyProvider != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		key, err := keyProvider.GetMasterKey(ctx)
		if err == nil && key != "" {
			if unlockErr := vm.Unlock(key); unlockErr != nil {
				slog.Error("Auto-unlock failed", "error", unlockErr)
			} else {
				slog.Info("Vault auto-unlocked successfully via KeyProvider")
			}
		}
	}

	return vm
}

func (m *VaultManager) IsLocked() bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.isLocked
}

// Unlock parses the master key and unlocks the vault if valid.
func (m *VaultManager) Unlock(masterKey string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	var parseErr error
	var identity *age.X25519Identity

	// Protect parsing inside secret.Do so temporary strings are zeroed
	secret.Do(func() {
		identity, parseErr = age.ParseX25519Identity(strings.TrimSpace(masterKey))
	})

	if parseErr != nil {
		return fmt.Errorf("invalid master key: %w", parseErr)
	}

	m.identity = identity
	m.isLocked = false
	return nil
}

func (m *VaultManager) LoadAndDecrypt(ctx context.Context) (*VaultTree, error) {
	m.mu.RLock()
	locked := m.isLocked
	identity := m.identity
	m.mu.RUnlock()

	if locked || identity == nil {
		return nil, ErrVaultLocked
	}

	sec, err := m.k8sClient.CoreV1().Secrets(m.config.VaultNamespace).Get(ctx, m.config.VaultSecretName, metav1.GetOptions{})
	if err != nil {
		if k8serrors.IsNotFound(err) {
			return &VaultTree{Nodes: make(map[string]*VaultNode)}, nil
		}
		return nil, err
	}

	ciphertext, ok := sec.Data["vault.enc"]
	if !ok || len(ciphertext) == 0 {
		return &VaultTree{Nodes: make(map[string]*VaultNode)}, nil
	}

	reader, err := age.Decrypt(bytes.NewReader(ciphertext), identity)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt vault: %w", err)
	}

	plaintext, err := io.ReadAll(reader)
	if err != nil {
		return nil, err
	}

	var tree VaultTree
	if err := json.Unmarshal(plaintext, &tree); err != nil {
		return nil, err
	}
	return &tree, nil
}

func (m *VaultManager) EncryptAndSave(ctx context.Context, tree *VaultTree) error {
	m.mu.RLock()
	locked := m.isLocked
	identity := m.identity
	m.mu.RUnlock()

	if locked || identity == nil {
		return ErrVaultLocked
	}

	plaintext, err := json.Marshal(tree)
	if err != nil {
		return err
	}

	var buf bytes.Buffer
	recipient := identity.Recipient()
	writer, err := age.Encrypt(&buf, recipient)
	if err != nil {
		return err
	}

	if _, err := writer.Write(plaintext); err != nil {
		return err
	}
	if err := writer.Close(); err != nil {
		return err
	}

	secretClient := m.k8sClient.CoreV1().Secrets(m.config.VaultNamespace)
	sec, err := secretClient.Get(ctx, m.config.VaultSecretName, metav1.GetOptions{})
	if err != nil {
		if k8serrors.IsNotFound(err) {
			_, err = secretClient.Create(ctx, &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{Name: m.config.VaultSecretName},
				Data:       map[string][]byte{"vault.enc": buf.Bytes()},
			}, metav1.CreateOptions{})
			return err
		}
		return err
	}

	if sec.Data == nil {
		sec.Data = make(map[string][]byte)
	}
	sec.Data["vault.enc"] = buf.Bytes()
	_, err = secretClient.Update(ctx, sec, metav1.UpdateOptions{})
	return err
}
