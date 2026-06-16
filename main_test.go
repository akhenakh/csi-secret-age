package main

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"testing"
	"time"

	"filippo.io/age"
	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"
	"sigs.k8s.io/secrets-store-csi-driver/provider/v1alpha1"
)

// Helper: Generate a throwaway age key for testing
func generateTestMasterKey(t *testing.T) string {
	identity, err := age.GenerateX25519Identity()
	require.NoError(t, err)
	return identity.String()
}

func getTestLogger() *slog.Logger {
	// Discard logs during tests to keep output clean
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func TestVaultNode_CanAccess(t *testing.T) {
	tests := []struct {
		name          string
		node          VaultNode
		testNamespace string
		testSA        string
		want          bool
	}{
		{
			name: "Wildcard allows everything",
			node: VaultNode{
				AllowedNamespaces:      []string{"*"},
				AllowedServiceAccounts: []string{"*"},
			},
			testNamespace: "random-ns",
			testSA:        "random-sa",
			want:          true,
		},
		{
			name: "Specific namespace and SA matches",
			node: VaultNode{
				AllowedNamespaces:      []string{"prod"},
				AllowedServiceAccounts: []string{"db-client"},
			},
			testNamespace: "prod",
			testSA:        "db-client",
			want:          true,
		},
		{
			name: "Namespace mismatch denies access",
			node: VaultNode{
				AllowedNamespaces:      []string{"prod"},
				AllowedServiceAccounts: []string{"db-client"},
			},
			testNamespace: "staging",
			testSA:        "db-client",
			want:          false,
		},
		{
			name: "ServiceAccount mismatch denies access",
			node: VaultNode{
				AllowedNamespaces:      []string{"prod"},
				AllowedServiceAccounts: []string{"db-client"},
			},
			testNamespace: "prod",
			testSA:        "web-client",
			want:          false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.node.CanAccess(tt.testNamespace, tt.testSA)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestVaultManager_EncryptAndLoad(t *testing.T) {
	ctx := context.Background()
	fakeClient := fake.NewSimpleClientset()
	cfg := Config{
		MasterKey:       generateTestMasterKey(t),
		VaultSecretName: "test-vault",
		VaultNamespace:  "kube-system",
	}

	// Use the EnvKeyProvider to mock passing the key, which auto-unlocks the manager
	keyProvider := &EnvKeyProvider{Key: cfg.MasterKey}
	mgr := NewVaultManager(cfg, fakeClient, keyProvider)

	// Verify the vault is unlocked
	require.False(t, mgr.IsLocked(), "Vault should be unlocked via the keyProvider")

	// 1. Loading an empty/non-existent vault should return an empty tree, not an error
	emptyTree, err := mgr.LoadAndDecrypt(ctx)
	require.NoError(t, err)
	require.NotNil(t, emptyTree)
	require.Empty(t, emptyTree.Nodes)

	// 2. Populate the tree and save it
	tree := &VaultTree{
		Nodes: map[string]*VaultNode{
			"/test/secret": {
				Value:                  "my-super-secret",
				AllowedNamespaces:      []string{"*"},
				AllowedServiceAccounts: []string{"*"},
			},
		},
	}
	err = mgr.EncryptAndSave(ctx, tree)
	require.NoError(t, err)

	// 3. Verify it was actually written to the fake K8s client
	k8sSecret, err := fakeClient.CoreV1().Secrets(cfg.VaultNamespace).Get(ctx, cfg.VaultSecretName, metav1.GetOptions{})
	require.NoError(t, err)
	require.Contains(t, k8sSecret.Data, "vault.enc")
	require.NotContains(t, string(k8sSecret.Data["vault.enc"]), "my-super-secret", "The K8s secret should be encrypted, plaintext must not be visible!")

	// 4. Load it back and verify contents
	loadedTree, err := mgr.LoadAndDecrypt(ctx)
	require.NoError(t, err)
	require.Contains(t, loadedTree.Nodes, "/test/secret")
	assert.Equal(t, "my-super-secret", loadedTree.Nodes["/test/secret"].Value)
}

func TestProviderServer_Mount(t *testing.T) {
	ctx := context.Background()
	fakeClient := fake.NewSimpleClientset()
	cfg := Config{
		MasterKey:       generateTestMasterKey(t),
		VaultSecretName: "test-vault",
		VaultNamespace:  "kube-system",
	}

	keyProvider := &EnvKeyProvider{Key: cfg.MasterKey}
	mgr := NewVaultManager(cfg, fakeClient, keyProvider)
	require.False(t, mgr.IsLocked(), "Vault should be unlocked")

	// Setup ProviderServer
	server := &ProviderServer{
		manager: mgr,
		logger:  getTestLogger(),
	}

	// Setup Vault Data
	tree := &VaultTree{
		Nodes: map[string]*VaultNode{
			"/db/pass": {
				Value:                  "db-secret-value",
				AllowedNamespaces:      []string{"prod"},
				AllowedServiceAccounts: []string{"app"},
			},
			"/api/key": {
				Value:                  "api-secret-value",
				AllowedNamespaces:      []string{"*"},
				AllowedServiceAccounts: []string{"*"},
			},
		},
	}
	require.NoError(t, mgr.EncryptAndSave(ctx, tree))

	// Helper to generate a mount request
	makeMountReq := func(ns, sa, secretsConfig string) *v1alpha1.MountRequest {
		attrs := map[string]string{
			"csi.storage.k8s.io/pod.namespace":       ns,
			"csi.storage.k8s.io/serviceAccount.name": sa,
			"secrets":                                secretsConfig,
		}
		attrBytes, _ := json.Marshal(attrs)
		return &v1alpha1.MountRequest{Attributes: string(attrBytes)}
	}

	tests := []struct {
		name          string
		req           *v1alpha1.MountRequest
		expectErr     bool
		errContains   string
		expectedFiles map[string]string
	}{
		{
			name:      "Successful mount single secret",
			req:       makeMountReq("prod", "app", "db-password=/db/pass"),
			expectErr: false,
			expectedFiles: map[string]string{
				"db-password": "db-secret-value",
			},
		},
		{
			name:      "Successful mount multiple secrets with spaces",
			req:       makeMountReq("prod", "app", " db-password = /db/pass , api-key = /api/key "),
			expectErr: false,
			expectedFiles: map[string]string{
				"db-password": "db-secret-value",
				"api-key":     "api-secret-value",
			},
		},
		{
			name:        "Access Denied due to wrong namespace",
			req:         makeMountReq("staging", "app", "db-password=/db/pass"),
			expectErr:   true,
			errContains: "access denied to path /db/pass",
		},
		{
			name:        "Access Denied due to wrong service account",
			req:         makeMountReq("prod", "web", "db-password=/db/pass"),
			expectErr:   true,
			errContains: "access denied to path /db/pass",
		},
		{
			name:        "Missing secret in vault",
			req:         makeMountReq("prod", "app", "missing=/does/not/exist"),
			expectErr:   true,
			errContains: "not found in vault",
		},
		{
			name: "Malformed attributes JSON",
			req: &v1alpha1.MountRequest{
				Attributes: "invalid-json",
			},
			expectErr:   true,
			errContains: "failed to unmarshal attributes",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resp, err := server.Mount(ctx, tt.req)

			if tt.expectErr {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.errContains)
				assert.Nil(t, resp)
			} else {
				require.NoError(t, err)
				require.NotNil(t, resp)
				assert.Len(t, resp.Files, len(tt.expectedFiles))

				// Verify mounted files match expected
				filesMap := make(map[string]string)
				for _, f := range resp.Files {
					filesMap[f.Path] = string(f.Contents)
				}
				for expectedName, expectedVal := range tt.expectedFiles {
					assert.Equal(t, expectedVal, filesMap[expectedName])
				}
			}
		})
	}
}

func TestProviderServer_Version(t *testing.T) {
	server := &ProviderServer{logger: getTestLogger()}
	resp, err := server.Version(context.Background(), &v1alpha1.VersionRequest{})
	require.NoError(t, err)
	assert.Equal(t, "v1alpha1", resp.Version)
	assert.Equal(t, "age-vault-provider", resp.RuntimeName)
}

func TestVaultManager_LockedState(t *testing.T) {
	ctx := context.Background()
	fakeClient := fake.NewSimpleClientset()
	cfg := Config{
		VaultSecretName: "test-vault",
		VaultNamespace:  "kube-system",
	}

	// 1. Initialize without a key provider (simulating missing key)
	mgr := NewVaultManager(cfg, fakeClient, nil)
	require.True(t, mgr.IsLocked())

	// 2. Trying to decrypt while locked should fail
	_, err := mgr.LoadAndDecrypt(ctx)
	require.ErrorIs(t, err, ErrVaultLocked)

	// 3. Trying to encrypt while locked should fail
	err = mgr.EncryptAndSave(ctx, &VaultTree{})
	require.ErrorIs(t, err, ErrVaultLocked)

	// 4. Unlock with a valid key
	masterKey := generateTestMasterKey(t)
	err = mgr.Unlock(masterKey)
	require.NoError(t, err)
	require.False(t, mgr.IsLocked())

	// 5. Operations should now succeed
	tree, err := mgr.LoadAndDecrypt(ctx)
	require.NoError(t, err)
	require.NotNil(t, tree)
}

func TestCheckPathConflict(t *testing.T) {
	tests := []struct {
		name      string
		tree      *VaultTree
		newPath   string
		isFolder  bool
		wantError string
	}{
		{
			name: "no conflict empty tree",
			tree: &VaultTree{Nodes: map[string]*VaultNode{}},
			newPath: "/nats/secret", isFolder: false,
			wantError: "",
		},
		{
			name: "conflict leaf already exists",
			tree: &VaultTree{Nodes: map[string]*VaultNode{
				"/nats/secret": {Value: "x", IsFolder: false},
			}},
			newPath: "/nats/secret", isFolder: true,
			wantError: "already exists as a secret",
		},
		{
			name: "conflict folder already exists",
			tree: &VaultTree{Nodes: map[string]*VaultNode{
				"/nats/secret": {IsFolder: true},
			}},
			newPath: "/nats/secret", isFolder: false,
			wantError: "already exists as a folder",
		},
		{
			name: "conflict leaf cannot have children",
			tree: &VaultTree{Nodes: map[string]*VaultNode{
				"/nats/secret": {Value: "x", IsFolder: false},
			}},
			newPath: "/nats", isFolder: false,
			wantError: "cannot have children",
		},
		{
			name: "conflict cannot create under leaf",
			tree: &VaultTree{Nodes: map[string]*VaultNode{
				"/nats": {Value: "x", IsFolder: false},
			}},
			newPath: "/nats/secret", isFolder: false,
			wantError: "under existing secret",
		},
		{
			name: "conflict cannot create folder under leaf",
			tree: &VaultTree{Nodes: map[string]*VaultNode{
				"/nats": {Value: "x", IsFolder: false},
			}},
			newPath: "/nats/secret", isFolder: true,
			wantError: "under existing secret",
		},
		{
			name: "allowed folder can have children",
			tree: &VaultTree{Nodes: map[string]*VaultNode{
				"/nats/secret": {Value: "x", IsFolder: false},
			}},
			newPath: "/nats", isFolder: true,
			wantError: "",
		},
		{
			name: "allowed update same type",
			tree: &VaultTree{Nodes: map[string]*VaultNode{
				"/nats/secret": {Value: "x", IsFolder: false},
			}},
			newPath: "/nats/secret", isFolder: false,
			wantError: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := checkPathConflict(tt.tree, tt.newPath, tt.isFolder)
			if tt.wantError == "" {
				assert.Empty(t, got)
			} else {
				assert.Contains(t, got, tt.wantError)
			}
		})
	}
}

func TestMatchPermission(t *testing.T) {
	tests := []struct {
		name    string
		pattern string
		path    string
		want    bool
	}{
		{"exact match", "/nats/secret", "/nats/secret", true},
		{"exact mismatch", "/nats/secret", "/nats/other", false},
		{"wildcard prefix exact", "/nats/*", "/nats", true},
		{"wildcard subpath", "/nats/*", "/nats/secret", true},
		{"wildcard deep subpath", "/nats/*", "/nats/a/b/c", true},
		{"wildcard mismatch", "/nats/*", "/natsx", false},
		{"wildcard sibling", "/nats/*", "/postgres/secret", false},
		{"root wildcard everything", "/*", "/anything", true},
		{"root wildcard root", "/*", "/", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := matchPermission(tt.pattern, tt.path)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestPermissionManager_Load(t *testing.T) {
	tmpDir := t.TempDir()
	permPath := filepath.Join(tmpDir, "perm.yaml")
	content := `
userA:
  - "/nats/*"
  - "/postgresql/*"
userB:
  - "/app/*"
admin:
  - userH
`
	require.NoError(t, os.WriteFile(permPath, []byte(content), 0644))

	pm, err := NewPermissionManager(permPath, "", "sub")
	require.Error(t, err) // public key is required

	// Generate a throwaway RSA key for the test
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	pubKeyBytes, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	require.NoError(t, err)
	pubKeyPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubKeyBytes})

	pm, err = NewPermissionManager(permPath, string(pubKeyPEM), "sub")
	require.NoError(t, err)

	userA := pm.GetUserPermissions("userA")
	require.NotNil(t, userA)
	assert.False(t, userA.isAdmin)
	assert.True(t, userA.CanRead("/nats/secret"))
	assert.True(t, userA.CanRead("/postgresql/db"))
	assert.False(t, userA.CanRead("/app/key"))

	userB := pm.GetUserPermissions("userB")
	require.NotNil(t, userB)
	assert.True(t, userB.CanRead("/app/key"))

	admin := pm.GetUserPermissions("userH")
	require.NotNil(t, admin)
	assert.True(t, admin.isAdmin)
	assert.True(t, admin.CanRead("/anything"))
	assert.True(t, admin.CanExport())
	assert.True(t, admin.CanWrite("/anything"))

	unknown := pm.GetUserPermissions("unknown")
	require.NotNil(t, unknown)
	assert.False(t, unknown.CanRead("/nats/secret"))
}

func TestPermissionManager_ValidateJWT(t *testing.T) {
	// Generate RSA key pair
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	pubKeyBytes, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	require.NoError(t, err)
	pubKeyPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubKeyBytes})

	tmpDir := t.TempDir()
	permPath := filepath.Join(tmpDir, "perm.yaml")
	require.NoError(t, os.WriteFile(permPath, []byte("admin:\n  - userH\n"), 0644))

	pm, err := NewPermissionManager(permPath, string(pubKeyPEM), "sub")
	require.NoError(t, err)

	// Valid token
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
		"sub": "userH",
		"exp": time.Now().Add(time.Hour).Unix(),
	})
	tokenString, err := token.SignedString(privateKey)
	require.NoError(t, err)

	username, err := pm.ValidateJWT(tokenString)
	require.NoError(t, err)
	assert.Equal(t, "userH", username)

	// Invalid token (wrong key)
	badPrivateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	badToken := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
		"sub": "userH",
		"exp": time.Now().Add(time.Hour).Unix(),
	})
	badTokenString, err := badToken.SignedString(badPrivateKey)
	require.NoError(t, err)

	_, err = pm.ValidateJWT(badTokenString)
	require.Error(t, err)

	// Missing claim
	noSubToken := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
		"exp": time.Now().Add(time.Hour).Unix(),
	})
	noSubTokenString, err := noSubToken.SignedString(privateKey)
	require.NoError(t, err)

	_, err = pm.ValidateJWT(noSubTokenString)
	require.Error(t, err)
}
