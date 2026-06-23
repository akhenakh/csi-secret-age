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
	nsMatch := false
	for _, allowed := range n.AllowedNamespaces {
		if allowed == namespace || allowed == "*" {
			nsMatch = true
			break
		}
	}
	saMatch := false
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

	// Protect parsing inside secret.Do so temporary strings are zeroed.
	// ParseIdentities (rather than ParseX25519Identity) is used so the key may
	// be supplied either as a bare AGE-SECRET-KEY-1... line or as a full
	// age-keygen file, which carries "# created" / "# public key" comment
	// headers. KMS/file-backed providers commonly return the latter.
	secret.Do(func() {
		ids, err := age.ParseIdentities(strings.NewReader(masterKey))
		if err != nil {
			parseErr = err
			return
		}
		for _, id := range ids {
			if x, ok := id.(*age.X25519Identity); ok {
				identity = x
				return
			}
		}
		parseErr = errors.New("no X25519 identity found in master key")
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

	var tree *VaultTree
	var decryptErr error
	secret.Do(func() {
		reader, err := age.Decrypt(bytes.NewReader(ciphertext), identity)
		if err != nil {
			decryptErr = fmt.Errorf("failed to decrypt vault: %w", err)
			return
		}

		plaintext, err := io.ReadAll(reader)
		if err != nil {
			decryptErr = err
			return
		}

		var t VaultTree
		if err := json.Unmarshal(plaintext, &t); err != nil {
			decryptErr = err
			return
		}
		tree = &t
	})
	if decryptErr != nil {
		return nil, decryptErr
	}
	return tree, nil
}

func encryptTree(tree *VaultTree, identity *age.X25519Identity) ([]byte, error) {
	var result []byte
	var encErr error
	secret.Do(func() {
		plaintext, err := json.Marshal(tree)
		if err != nil {
			encErr = err
			return
		}

		var buf bytes.Buffer
		recipient := identity.Recipient()
		writer, err := age.Encrypt(&buf, recipient)
		if err != nil {
			encErr = err
			return
		}
		if _, err := writer.Write(plaintext); err != nil {
			encErr = err
			return
		}
		if err := writer.Close(); err != nil {
			encErr = err
			return
		}
		result = buf.Bytes()
	})
	if encErr != nil {
		return nil, encErr
	}
	return result, nil
}

func (m *VaultManager) EncryptAndSave(ctx context.Context, tree *VaultTree) error {
	m.mu.RLock()
	locked := m.isLocked
	identity := m.identity
	m.mu.RUnlock()

	if locked || identity == nil {
		return ErrVaultLocked
	}

	ciphertext, err := encryptTree(tree, identity)
	if err != nil {
		return err
	}

	secretClient := m.k8sClient.CoreV1().Secrets(m.config.VaultNamespace)
	sec, err := secretClient.Get(ctx, m.config.VaultSecretName, metav1.GetOptions{})
	if err != nil {
		if k8serrors.IsNotFound(err) {
			_, err = secretClient.Create(ctx, &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{Name: m.config.VaultSecretName},
				Data:       map[string][]byte{"vault.enc": ciphertext},
			}, metav1.CreateOptions{})
			return err
		}
		return err
	}

	if sec.Data == nil {
		sec.Data = make(map[string][]byte)
	}
	sec.Data["vault.enc"] = ciphertext
	_, err = secretClient.Update(ctx, sec, metav1.UpdateOptions{})
	return err
}

// UpdateVault performs a read-modify-write cycle on the Kubernetes Secret
// with optimistic locking. If the Secret is modified by another process
// between the read and the write, the update is retried (up to 5 times).
func (m *VaultManager) UpdateVault(ctx context.Context, modifier func(*VaultTree) error) error {
	m.mu.RLock()
	locked := m.isLocked
	identity := m.identity
	m.mu.RUnlock()

	if locked || identity == nil {
		return ErrVaultLocked
	}

	const maxRetries = 5
	secretClient := m.k8sClient.CoreV1().Secrets(m.config.VaultNamespace)

	for attempt := 0; attempt < maxRetries; attempt++ {
		sec, err := secretClient.Get(ctx, m.config.VaultSecretName, metav1.GetOptions{})
		if err != nil {
			if k8serrors.IsNotFound(err) {
				// Secret doesn't exist yet; create it.
				tree := &VaultTree{Nodes: make(map[string]*VaultNode)}
				if err := modifier(tree); err != nil {
					return err
				}
				ciphertext, err := encryptTree(tree, identity)
				if err != nil {
					return err
				}
				_, err = secretClient.Create(ctx, &corev1.Secret{
					ObjectMeta: metav1.ObjectMeta{Name: m.config.VaultSecretName},
					Data:       map[string][]byte{"vault.enc": ciphertext},
				}, metav1.CreateOptions{})
				if err != nil && k8serrors.IsAlreadyExists(err) {
					continue // another writer created it first; re-fetch and merge
				}
				return err
			}
			return err
		}

		var tree *VaultTree
		if ciphertext, ok := sec.Data["vault.enc"]; ok && len(ciphertext) > 0 {
			reader, err := age.Decrypt(bytes.NewReader(ciphertext), identity)
			if err != nil {
				return fmt.Errorf("failed to decrypt vault: %w", err)
			}
			plaintext, err := io.ReadAll(reader)
			if err != nil {
				return err
			}
			tree = &VaultTree{}
			if err := json.Unmarshal(plaintext, tree); err != nil {
				return err
			}
		} else {
			tree = &VaultTree{Nodes: make(map[string]*VaultNode)}
		}

		if err := modifier(tree); err != nil {
			return err
		}

		ciphertext, err := encryptTree(tree, identity)
		if err != nil {
			return err
		}

		sec.Data["vault.enc"] = ciphertext
		_, err = secretClient.Update(ctx, sec, metav1.UpdateOptions{})
		if err == nil {
			return nil
		}
		if k8serrors.IsConflict(err) {
			if attempt < maxRetries-1 {
				time.Sleep(time.Duration(attempt+1) * 50 * time.Millisecond)
				continue
			}
		}
		return err
	}

	return fmt.Errorf("failed to update vault after %d attempts due to conflicts", maxRetries)
}
