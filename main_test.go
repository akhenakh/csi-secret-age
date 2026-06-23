package main

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"filippo.io/age"
	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	corev1 "k8s.io/api/core/v1"
	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/fake"
	k8stesting "k8s.io/client-go/testing"
	"sigs.k8s.io/secrets-store-csi-driver/provider/v1alpha1"
)

// Helper: Generate a throwaway age key for testing
func generateTestMasterKey(tb testing.TB) string {
	identity, err := age.GenerateX25519Identity()
	require.NoError(tb, err)
	return identity.String()
}

func getTestLogger() *slog.Logger {
	// Discard logs during tests to keep output clean
	return slog.New(slog.NewTextHandler(io.Discard, nil))
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
				Value: "my-super-secret",
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
				Value: "db-secret-value",
			},
			"/api/key": {
				Value: "api-secret-value",
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
	assert.Equal(t, "csi-secret-age-provider", resp.RuntimeName)
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

// TestUnlockWithKeygenFileFormat is a regression test for the case where the
// master key is provided as a full age-keygen file (with "# created" /
// "# public key" comment headers) rather than a bare AGE-SECRET-KEY-1 line.
// KMS and file-backed providers commonly return this format; Unlock must
// tolerate it instead of failing with "malformed secret key".
func TestUnlockWithKeygenFileFormat(t *testing.T) {
	ctx := context.Background()
	fakeClient := fake.NewSimpleClientset()
	cfg := Config{
		VaultSecretName: "test-vault",
		VaultNamespace:  "kube-system",
	}

	identity, err := age.GenerateX25519Identity()
	require.NoError(t, err)

	// Reproduce the exact format emitted by `age-keygen`.
	keygenFile := fmt.Sprintf(
		"# created: 2026-06-22T16:08:32-04:00\n# public key: %s\n%s\n",
		identity.Recipient().String(),
		identity.String(),
	)

	mgr := NewVaultManager(cfg, fakeClient, nil)
	require.True(t, mgr.IsLocked())

	err = mgr.Unlock(keygenFile)
	require.NoError(t, err, "Unlock must accept a full age-keygen file")
	require.False(t, mgr.IsLocked())

	// Prove the parsed identity is the correct one by round-tripping the vault.
	tree := &VaultTree{Nodes: map[string]*VaultNode{
		"/secret": {Value: "shhh"},
	}}
	require.NoError(t, mgr.EncryptAndSave(ctx, tree))

	loaded, err := mgr.LoadAndDecrypt(ctx)
	require.NoError(t, err)
	require.Equal(t, "shhh", loaded.Nodes["/secret"].Value)
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
			name:    "no conflict empty tree",
			tree:    &VaultTree{Nodes: map[string]*VaultNode{}},
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
admin_users:
  - userH
user_permissions:
  userA:
    - "/nats/*"
    - "/postgresql/*"
  userB:
    - "/app/*"
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

func TestPermissionManager_CanAccess(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	pubKeyBytes, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	require.NoError(t, err)
	pubKeyPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubKeyBytes})

	tests := []struct {
		name string
		yaml string
		ns   string
		sa   string
		path string
		want bool
	}{
		{
			name: "empty namespace_permissions denies all",
			yaml: `
user_permissions:
  userA:
    - "/nats/*"
`,
			ns: "staging", sa: "web", path: "/any/secret",
			want: false,
		},
		{
			name: "namespace matches pattern",
			yaml: `
namespace_permissions:
  staging:
    - "/staging/*"
`,
			ns: "staging", sa: "web", path: "/staging/db/pass",
			want: true,
		},
		{
			name: "namespace matches but path does not",
			yaml: `
namespace_permissions:
  staging:
    - "/staging/*"
`,
			ns: "staging", sa: "web", path: "/prod/secret",
			want: false,
		},
		{
			name: "namespace not in config is denied",
			yaml: `
namespace_permissions:
  staging:
    - "/staging/*"
`,
			ns: "prod", sa: "app", path: "/any/secret",
			want: false,
		},
		{
			name: "namespace and sa match pattern",
			yaml: `
namespace_permissions:
  staging/web:
    - "/staging/web/*"
`,
			ns: "staging", sa: "web", path: "/staging/web/key",
			want: true,
		},
		{
			name: "sa-specific restriction takes precedence over namespace",
			yaml: `
namespace_permissions:
  staging:
    - "/staging/*"
  staging/db:
    - "/staging/db/*"
`,
			ns: "staging", sa: "db", path: "/staging/app/secret",
			want: false,
		},
		{
			name: "sa-specific allows when namespace would also match",
			yaml: `
namespace_permissions:
  staging/db:
    - "/staging/db/*"
`,
			ns: "staging", sa: "db", path: "/staging/db/pass",
			want: true,
		},
		{
			name: "nil PermissionManager allows all",
			ns:   "staging", sa: "web", path: "/any/secret",
			want: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var pm *PermissionManager
			if tt.yaml != "" {
				permPath := filepath.Join(t.TempDir(), "perm.yaml")
				require.NoError(t, os.WriteFile(permPath, []byte(tt.yaml), 0644))
				pm, err = NewPermissionManager(permPath, string(pubKeyPEM), "sub")
				require.NoError(t, err)
			}
			got := pm.CanAccess(tt.ns, tt.sa, tt.path)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestProviderServer_Mount_NamespacePermissions(t *testing.T) {
	ctx := context.Background()
	fakeClient := fake.NewSimpleClientset()
	cfg := Config{
		MasterKey:       generateTestMasterKey(t),
		VaultSecretName: "test-vault",
		VaultNamespace:  "kube-system",
	}

	keyProvider := &EnvKeyProvider{Key: cfg.MasterKey}
	mgr := NewVaultManager(cfg, fakeClient, keyProvider)
	require.False(t, mgr.IsLocked())

	tree := &VaultTree{
		Nodes: map[string]*VaultNode{
			"/staging/db/pass": {
				Value: "staging-db-secret",
			},
			"/prod/api/key": {
				Value: "prod-api-secret",
			},
		},
	}
	require.NoError(t, mgr.EncryptAndSave(ctx, tree))

	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	pubKeyBytes, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	require.NoError(t, err)
	pubKeyPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubKeyBytes})

	permPath := filepath.Join(t.TempDir(), "perm.yaml")
	permYAML := `
namespace_permissions:
  staging:
    - "/staging/*"
  prod/web:
    - "/prod/web/*"
`
	require.NoError(t, os.WriteFile(permPath, []byte(permYAML), 0644))
	permMgr, err := NewPermissionManager(permPath, string(pubKeyPEM), "sub")
	require.NoError(t, err)

	server := &ProviderServer{
		manager: mgr,
		permMgr: permMgr,
		logger:  getTestLogger(),
	}

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
		name        string
		req         *v1alpha1.MountRequest
		expectErr   bool
		errContains string
	}{
		{
			name:      "staging namespace can read staging secrets",
			req:       makeMountReq("staging", "any", "db=/staging/db/pass"),
			expectErr: false,
		},
		{
			name:        "staging namespace denied from prod secrets",
			req:         makeMountReq("staging", "any", "key=/prod/api/key"),
			expectErr:   true,
			errContains: "access denied to path /prod/api/key",
		},
		{
			name:        "prod/web SA denied from staging secrets",
			req:         makeMountReq("prod", "web", "db=/staging/db/pass"),
			expectErr:   true,
			errContains: "access denied to path /staging/db/pass",
		},
		{
			name:        "unlisted namespace is denied",
			req:         makeMountReq("dev", "any", "db=/staging/db/pass"),
			expectErr:   true,
			errContains: "access denied to path /staging/db/pass",
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
			}
		})
	}
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
	require.NoError(t, os.WriteFile(permPath, []byte("admin_users:\n  - userH\n"), 0644))

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

// helper to build a minimal JWKS JSON document from an RSA public key.
func generateTestJWKS(t testing.TB, privateKey *rsa.PrivateKey, kid string) string {
	t.Helper()
	n := base64.RawURLEncoding.EncodeToString(privateKey.PublicKey.N.Bytes())
	e := base64.RawURLEncoding.EncodeToString(big.NewInt(int64(privateKey.PublicKey.E)).Bytes())
	jwks := map[string]any{
		"keys": []map[string]any{
			{"kty": "RSA", "kid": kid, "n": n, "e": e, "alg": "RS256", "use": "sig"},
		},
	}
	b, err := json.Marshal(jwks)
	require.NoError(t, err)
	return string(b)
}

func signTestTokenWithKID(tb testing.TB, privateKey *rsa.PrivateKey, kid, user string) string {
	tb.Helper()
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
		"sub": user,
		"exp": time.Now().Add(time.Hour).Unix(),
	})
	token.Header["kid"] = kid
	signed, err := token.SignedString(privateKey)
	require.NoError(tb, err)
	return signed
}

func TestPermissionManager_ValidateJWT_StaticJWKS(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	tmpDir := t.TempDir()
	permPath := filepath.Join(tmpDir, "perm.yaml")
	require.NoError(t, os.WriteFile(permPath, []byte("admin_users:\n  - userH\n"), 0644))

	jwksJSON := generateTestJWKS(t, privateKey, "key1")
	pm, err := NewPermissionManagerWithJWTConfig(permPath, JWTKeyConfig{JWKSJSON: jwksJSON}, "sub")
	require.NoError(t, err)

	validToken := signTestTokenWithKID(t, privateKey, "key1", "userH")
	username, err := pm.ValidateJWT(validToken)
	require.NoError(t, err)
	assert.Equal(t, "userH", username)

	// Token signed with an unknown kid should be rejected.
	unknownKIDToken := signTestTokenWithKID(t, privateKey, "unknown", "userH")
	_, err = pm.ValidateJWT(unknownKIDToken)
	require.Error(t, err)

	// Token without a kid should be rejected.
	noKIDToken := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
		"sub": "userH",
		"exp": time.Now().Add(time.Hour).Unix(),
	})
	noKIDTokenString, err := noKIDToken.SignedString(privateKey)
	require.NoError(t, err)
	_, err = pm.ValidateJWT(noKIDTokenString)
	require.Error(t, err)
}

func TestPermissionManager_ValidateJWT_JWKSURL(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	jwksJSON := generateTestJWKS(t, privateKey, "rotatable")

	requests := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(jwksJSON))
	}))
	defer server.Close()

	tmpDir := t.TempDir()
	permPath := filepath.Join(tmpDir, "perm.yaml")
	require.NoError(t, os.WriteFile(permPath, []byte("admin_users:\n  - userH\n"), 0644))

	pm, err := NewPermissionManagerWithJWTConfig(permPath, JWTKeyConfig{
		JWKSURL:         server.URL,
		RefreshInterval: time.Hour, // long TTL to test caching
	}, "sub")
	require.NoError(t, err)

	validToken := signTestTokenWithKID(t, privateKey, "rotatable", "userH")

	username, err := pm.ValidateJWT(validToken)
	require.NoError(t, err)
	assert.Equal(t, "userH", username)

	// A second validation should hit the in-memory cache, not the server.
	_, err = pm.ValidateJWT(validToken)
	require.NoError(t, err)
	assert.Equal(t, 1, requests, "expected JWKS to be fetched exactly once within the cache TTL")

	// With a zero TTL, every validation should refetch.
	pmNoCache, err := NewPermissionManagerWithJWTConfig(permPath, JWTKeyConfig{
		JWKSURL:         server.URL,
		RefreshInterval: 0,
	}, "sub")
	require.NoError(t, err)

	requestsBefore := requests
	_, err = pmNoCache.ValidateJWT(validToken)
	require.NoError(t, err)
	_, err = pmNoCache.ValidateJWT(validToken)
	require.NoError(t, err)
	assert.Equal(t, requestsBefore+2, requests, "expected a refetch per validation with zero TTL")
}

func TestPermissionManager_JWTKeyConfigConflicts(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	pubKeyBytes, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	require.NoError(t, err)
	pubKeyPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubKeyBytes})
	jwksJSON := generateTestJWKS(t, privateKey, "key1")

	tmpDir := t.TempDir()
	permPath := filepath.Join(tmpDir, "perm.yaml")
	require.NoError(t, os.WriteFile(permPath, []byte("admin_users:\n  - userH\n"), 0644))

	_, err = NewPermissionManagerWithJWTConfig(permPath, JWTKeyConfig{
		PublicKeyPEM: string(pubKeyPEM),
		JWKSURL:      "http://example.com/jwks",
	}, "sub")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "only one JWT key source")

	_, err = NewPermissionManagerWithJWTConfig(permPath, JWTKeyConfig{
		PublicKeyPEM: string(pubKeyPEM),
		JWKSJSON:     jwksJSON,
	}, "sub")
	require.Error(t, err)

	_, err = NewPermissionManagerWithJWTConfig(permPath, JWTKeyConfig{}, "sub")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "JWT public key or JWKS configuration is required")
}

// buildBenchmarkTree creates a tree with n nodes, each node is a leaf with a 64-byte secret.
func buildBenchmarkTree(n int) *VaultTree {
	tree := &VaultTree{Nodes: make(map[string]*VaultNode, n)}
	for i := 0; i < n; i++ {
		path := fmt.Sprintf("/app/%d/secret", i)
		tree.Nodes[path] = &VaultNode{
			Value: "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789",
		}
	}
	return tree
}

func BenchmarkVaultManager_LoadAndDecrypt_Small(b *testing.B) {
	ctx := context.Background()
	masterKey := generateTestMasterKey(b)
	cfg := Config{MasterKey: masterKey, VaultSecretName: "bench-vault", VaultNamespace: "kube-system"}
	mgr := NewVaultManager(cfg, fake.NewSimpleClientset(), &EnvKeyProvider{Key: masterKey})

	require.NoError(b, mgr.EncryptAndSave(ctx, buildBenchmarkTree(10)))

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := mgr.LoadAndDecrypt(ctx)
		require.NoError(b, err)
	}
}

func BenchmarkVaultManager_LoadAndDecrypt_Medium(b *testing.B) {
	ctx := context.Background()
	masterKey := generateTestMasterKey(b)
	cfg := Config{MasterKey: masterKey, VaultSecretName: "bench-vault", VaultNamespace: "kube-system"}
	mgr := NewVaultManager(cfg, fake.NewSimpleClientset(), &EnvKeyProvider{Key: masterKey})

	require.NoError(b, mgr.EncryptAndSave(ctx, buildBenchmarkTree(100)))

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := mgr.LoadAndDecrypt(ctx)
		require.NoError(b, err)
	}
}

func BenchmarkVaultManager_LoadAndDecrypt_Large(b *testing.B) {
	ctx := context.Background()
	masterKey := generateTestMasterKey(b)
	cfg := Config{MasterKey: masterKey, VaultSecretName: "bench-vault", VaultNamespace: "kube-system"}
	mgr := NewVaultManager(cfg, fake.NewSimpleClientset(), &EnvKeyProvider{Key: masterKey})

	require.NoError(b, mgr.EncryptAndSave(ctx, buildBenchmarkTree(1000)))

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := mgr.LoadAndDecrypt(ctx)
		require.NoError(b, err)
	}
}

func BenchmarkProviderServer_Mount(b *testing.B) {
	ctx := context.Background()
	fakeClient := fake.NewSimpleClientset()
	masterKey := generateTestMasterKey(b)
	cfg := Config{MasterKey: masterKey, VaultSecretName: "bench-vault", VaultNamespace: "kube-system"}
	mgr := NewVaultManager(cfg, fakeClient, &EnvKeyProvider{Key: masterKey})

	require.NoError(b, mgr.EncryptAndSave(ctx, buildBenchmarkTree(100)))

	server := &ProviderServer{manager: mgr, logger: getTestLogger()}
	req := &v1alpha1.MountRequest{
		Attributes: func() string {
			attrs := map[string]string{
				"csi.storage.k8s.io/pod.namespace":       "prod",
				"csi.storage.k8s.io/serviceAccount.name": "app",
				"secrets":                                "secret0=/app/0/secret",
			}
			b, _ := json.Marshal(attrs)
			return string(b)
		}(),
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := server.Mount(ctx, req)
		require.NoError(b, err)
	}
}

func TestVaultManager_UpdateVault(t *testing.T) {
	ctx := context.Background()
	fakeClient := fake.NewSimpleClientset()
	cfg := Config{
		MasterKey:       generateTestMasterKey(t),
		VaultSecretName: "test-vault",
		VaultNamespace:  "kube-system",
	}
	keyProvider := &EnvKeyProvider{Key: cfg.MasterKey}
	mgr := NewVaultManager(cfg, fakeClient, keyProvider)
	require.False(t, mgr.IsLocked())

	// Initial update should create the secret
	err := mgr.UpdateVault(ctx, func(tree *VaultTree) error {
		tree.Nodes["/db/pass"] = &VaultNode{
			Value: "secret",
		}
		return nil
	})
	require.NoError(t, err)

	loaded, err := mgr.LoadAndDecrypt(ctx)
	require.NoError(t, err)
	assert.Equal(t, "secret", loaded.Nodes["/db/pass"].Value)

	// Second update should modify
	err = mgr.UpdateVault(ctx, func(tree *VaultTree) error {
		tree.Nodes["/db/pass"].Value = "updated"
		return nil
	})
	require.NoError(t, err)

	loaded, err = mgr.LoadAndDecrypt(ctx)
	require.NoError(t, err)
	assert.Equal(t, "updated", loaded.Nodes["/db/pass"].Value)
}

func TestVaultManager_UpdateVault_Conflict(t *testing.T) {
	ctx := context.Background()
	fakeClient := fake.NewSimpleClientset()
	cfg := Config{
		MasterKey:       generateTestMasterKey(t),
		VaultSecretName: "test-vault",
		VaultNamespace:  "kube-system",
	}
	keyProvider := &EnvKeyProvider{Key: cfg.MasterKey}
	mgr := NewVaultManager(cfg, fakeClient, keyProvider)
	require.False(t, mgr.IsLocked())

	// Prepopulate
	tree := &VaultTree{Nodes: map[string]*VaultNode{
		"/db/pass": {Value: "initial"},
	}}
	require.NoError(t, mgr.EncryptAndSave(ctx, tree))

	// Inject a conflict on the first update attempt
	conflictCount := 0
	fakeClient.PrependReactor("update", "secrets", func(action k8stesting.Action) (handled bool, ret runtime.Object, err error) {
		if conflictCount == 0 {
			conflictCount++
			return true, nil, k8serrors.NewConflict(corev1.Resource("secrets"), cfg.VaultSecretName, errors.New("simulated conflict"))
		}
		return false, nil, nil
	})

	err := mgr.UpdateVault(ctx, func(tree *VaultTree) error {
		tree.Nodes["/db/pass"].Value = "updated-after-conflict"
		return nil
	})
	require.NoError(t, err)
	assert.Equal(t, 1, conflictCount, "expected one conflict to be simulated")

	loaded, err := mgr.LoadAndDecrypt(ctx)
	require.NoError(t, err)
	assert.Equal(t, "updated-after-conflict", loaded.Nodes["/db/pass"].Value)
}

func TestResolveSecretValue(t *testing.T) {
	tmpDir := t.TempDir()

	keyFile := filepath.Join(tmpDir, "master.key")
	require.NoError(t, os.WriteFile(keyFile, []byte("  AGE-SECRET-KEY-FROM-FILE  \n"), 0600))

	tests := []struct {
		name     string
		inline   string
		filePath string
		want     string
		wantErr  bool
	}{
		{
			name:   "inline only",
			inline: "inline-value",
			want:   "inline-value",
		},
		{
			name:     "file only",
			filePath: keyFile,
			want:     "AGE-SECRET-KEY-FROM-FILE",
		},
		{
			name:     "file takes precedence over inline",
			inline:   "inline-value",
			filePath: keyFile,
			want:     "AGE-SECRET-KEY-FROM-FILE",
		},
		{
			name:     "both empty",
			inline:   "",
			filePath: "",
			want:     "",
		},
		{
			name:     "file not found",
			filePath: filepath.Join(tmpDir, "nonexistent"),
			wantErr:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := resolveSecretValue(tt.inline, tt.filePath)
			if tt.wantErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
				assert.Equal(t, tt.want, got)
			}
		})
	}
}

func TestConfig_ResolveSecrets(t *testing.T) {
	tmpDir := t.TempDir()

	masterKeyFile := filepath.Join(tmpDir, "master.key")
	require.NoError(t, os.WriteFile(masterKeyFile, []byte("AGE-SECRET-KEY-MASTER\n"), 0600))

	kmsFile := filepath.Join(tmpDir, "kms.ct")
	require.NoError(t, os.WriteFile(kmsFile, []byte("base64-kms-ciphertext\n"), 0600))

	gcpKeyFile := filepath.Join(tmpDir, "gcp-keyname")
	require.NoError(t, os.WriteFile(gcpKeyFile, []byte("projects/p/locations/l/keyRings/kr/cryptoKeys/ck\n"), 0600))

	gcpCtFile := filepath.Join(tmpDir, "gcp.ct")
	require.NoError(t, os.WriteFile(gcpCtFile, []byte("base64-gcp-ciphertext\n"), 0600))

	jwtFile := filepath.Join(tmpDir, "jwt.pem")
	require.NoError(t, os.WriteFile(jwtFile, []byte("-----BEGIN PUBLIC KEY-----\nfake\n-----END PUBLIC KEY-----\n"), 0600))

	cfg := Config{
		MasterKeyFile:        masterKeyFile,
		KMSCiphertextFile:    kmsFile,
		GCPKMSKeyNameFile:    gcpKeyFile,
		GCPKMSCiphertextFile: gcpCtFile,
		JWTPublicKeyFile:     jwtFile,
	}
	require.NoError(t, cfg.ResolveSecrets())

	assert.Equal(t, "AGE-SECRET-KEY-MASTER", cfg.MasterKey)
	assert.Equal(t, "base64-kms-ciphertext", cfg.KMSCiphertext)
	assert.Equal(t, "projects/p/locations/l/keyRings/kr/cryptoKeys/ck", cfg.GCPKMSKeyName)
	assert.Equal(t, "base64-gcp-ciphertext", cfg.GCPKMSCiphertext)
	assert.Contains(t, cfg.JWTPublicKey, "BEGIN PUBLIC KEY")

	// JWKS file resolution
	jwksFile := filepath.Join(tmpDir, "jwks.json")
	require.NoError(t, os.WriteFile(jwksFile, []byte(`{"keys":[{"kty":"RSA","kid":"k1","n":"abc","e":"AQAB","alg":"RS256"}]}`), 0600))
	cfgJWKS := Config{JWTJWKSFile: jwksFile}
	require.NoError(t, cfgJWKS.ResolveSecrets())
	assert.Contains(t, cfgJWKS.JWTJWKS, "keys")

	cfg2 := Config{
		MasterKey:     "inline-key",
		KMSCiphertext: "inline-ct",
	}
	require.NoError(t, cfg2.ResolveSecrets())
	assert.Equal(t, "inline-key", cfg2.MasterKey)
	assert.Equal(t, "inline-ct", cfg2.KMSCiphertext)

	cfg3 := Config{
		MasterKeyFile: filepath.Join(tmpDir, "missing"),
	}
	require.Error(t, cfg3.ResolveSecrets())
}
