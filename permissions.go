package main

import (
	"context"
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
	"os"
	"strings"
	"sync"
	"time"

	"github.com/fsnotify/fsnotify"
	"github.com/golang-jwt/jwt/v5"
	"gopkg.in/yaml.v3"
)

type PermissionManager struct {
	configPath string
	keyfunc    jwt.Keyfunc
	userClaim  string
	audience   string
	issuer     string

	mu                   sync.RWMutex
	permissions          map[string][]string
	admins               []string
	namespacePermissions map[string][]string
}

// JWTKeyConfig selects the source of the RSA public key used to validate JWTs.
// Exactly one of PublicKeyPEM, JWKSURL, or JWKSJSON must be set.
type JWTKeyConfig struct {
	PublicKeyPEM    string
	JWKSURL         string
	JWKSJSON        string
	RefreshInterval time.Duration
	Audience        string
	Issuer          string
}

// UserPermissions holds the resolved permissions for a single user.
type UserPermissions struct {
	username string
	isAdmin  bool
	patterns []string
}

// NewPermissionManager creates a PermissionManager using a PEM-encoded RSA public key.
// It is kept for backward compatibility; new code should use NewPermissionManagerWithJWTConfig.
func NewPermissionManager(configPath, publicKeyPEM, userClaim string) (*PermissionManager, error) {
	return NewPermissionManagerWithJWTConfig(configPath, JWTKeyConfig{PublicKeyPEM: publicKeyPEM}, userClaim)
}

// NewPermissionManagerWithJWTConfig creates a PermissionManager from a JWT key
// configuration. Either a static RSA public key or a JWKS (URL or inline JSON)
// may be provided, but not more than one.
func NewPermissionManagerWithJWTConfig(configPath string, cfg JWTKeyConfig, userClaim string) (*PermissionManager, error) {
	if configPath == "" {
		return nil, errors.New("config path is required")
	}
	if userClaim == "" {
		userClaim = "sub"
	}

	keyfunc, err := buildJWTKeyfunc(cfg)
	if err != nil {
		return nil, err
	}

	pm := &PermissionManager{
		configPath: configPath,
		keyfunc:    keyfunc,
		userClaim:  userClaim,
		audience:   cfg.Audience,
		issuer:     cfg.Issuer,
	}

	if err := pm.Load(); err != nil {
		return nil, err
	}

	return pm, nil
}

func parseRSAPublicKey(pemStr string) (*rsa.PublicKey, error) {
	block, _ := pem.Decode([]byte(pemStr))
	if block == nil {
		return nil, errors.New("failed to decode PEM block")
	}
	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		pub, err = x509.ParsePKCS1PublicKey(block.Bytes)
		if err != nil {
			return nil, err
		}
	}
	rsaPub, ok := pub.(*rsa.PublicKey)
	if !ok {
		return nil, errors.New("not an RSA public key")
	}
	return rsaPub, nil
}

func buildJWTKeyfunc(cfg JWTKeyConfig) (jwt.Keyfunc, error) {
	sourcesSet := 0
	if cfg.PublicKeyPEM != "" {
		sourcesSet++
	}
	if cfg.JWKSURL != "" {
		sourcesSet++
	}
	if cfg.JWKSJSON != "" {
		sourcesSet++
	}
	if sourcesSet == 0 {
		return nil, errors.New("JWT public key or JWKS configuration is required")
	}
	if sourcesSet > 1 {
		return nil, errors.New("only one JWT key source may be configured: JWT_PUBLIC_KEY, JWT_JWKS_URL, or JWT_JWKS/JWT_JWKS_FILE")
	}

	if cfg.PublicKeyPEM != "" {
		return staticKeyfuncFromPEM(cfg.PublicKeyPEM)
	}
	if cfg.JWKSJSON != "" {
		return staticKeyfuncFromJWKS([]byte(cfg.JWKSJSON))
	}
	return newJWKSKeyfunc(cfg.JWKSURL, cfg.RefreshInterval)
}

func staticKeyfuncFromPEM(pemStr string) (jwt.Keyfunc, error) {
	pubKey, err := parseRSAPublicKey(pemStr)
	if err != nil {
		return nil, fmt.Errorf("failed to parse JWT public key: %w", err)
	}
	return func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return pubKey, nil
	}, nil
}

// jwk is a minimal JWK representation supporting RSA keys.
type jwk struct {
	Kty string `json:"kty"`
	Kid string `json:"kid"`
	N   string `json:"n"`
	E   string `json:"e"`
	Alg string `json:"alg"`
	Use string `json:"use"`
}

type jwksResponse struct {
	Keys []jwk `json:"keys"`
}

func parseRSAPublicKeyFromJWK(key jwk) (*rsa.PublicKey, error) {
	if key.Kty != "RSA" {
		return nil, fmt.Errorf("unsupported key type %q", key.Kty)
	}
	nBytes, err := base64.RawURLEncoding.DecodeString(key.N)
	if err != nil {
		return nil, fmt.Errorf("invalid key %q modulus: %w", key.Kid, err)
	}
	eBytes, err := base64.RawURLEncoding.DecodeString(key.E)
	if err != nil {
		return nil, fmt.Errorf("invalid key %q exponent: %w", key.Kid, err)
	}
	return &rsa.PublicKey{
		N: new(big.Int).SetBytes(nBytes),
		E: int(new(big.Int).SetBytes(eBytes).Int64()),
	}, nil
}

func parseJWKSKeys(data []byte) (map[string]*rsa.PublicKey, error) {
	var resp jwksResponse
	if err := json.Unmarshal(data, &resp); err != nil {
		return nil, fmt.Errorf("failed to parse JWKS JSON: %w", err)
	}
	keys := make(map[string]*rsa.PublicKey, len(resp.Keys))
	for _, key := range resp.Keys {
		if key.Kty != "RSA" {
			continue
		}
		if key.Use != "" && key.Use != "sig" {
			continue
		}
		pub, err := parseRSAPublicKeyFromJWK(key)
		if err != nil {
			return nil, err
		}
		if key.Kid == "" {
			continue
		}
		keys[key.Kid] = pub
	}
	if len(keys) == 0 {
		return nil, errors.New("JWKS contains no usable RSA signing keys")
	}
	return keys, nil
}

func staticKeyfuncFromJWKS(data []byte) (jwt.Keyfunc, error) {
	keys, err := parseJWKSKeys(data)
	if err != nil {
		return nil, err
	}
	return func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		kid, ok := token.Header["kid"].(string)
		if !ok || kid == "" {
			return nil, errors.New("token header missing kid")
		}
		pub, ok := keys[kid]
		if !ok {
			return nil, fmt.Errorf("JWKS does not contain key %q", kid)
		}
		return pub, nil
	}, nil
}

type jwksCache struct {
	url       string
	client    *http.Client
	refresh   time.Duration
	keys      map[string]*rsa.PublicKey
	lastFetch time.Time
	mu        sync.RWMutex
}

func newJWKSKeyfunc(url string, refresh time.Duration) (jwt.Keyfunc, error) {
	cache := &jwksCache{
		url:     url,
		client:  &http.Client{Timeout: 10 * time.Second},
		refresh: refresh,
	}
	return func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		kid, ok := token.Header["kid"].(string)
		if !ok || kid == "" {
			return nil, errors.New("token header missing kid")
		}
		pub, err := cache.getKey(kid)
		if err != nil {
			return nil, fmt.Errorf("JWKS lookup failed: %w", err)
		}
		return pub, nil
	}, nil
}

func (c *jwksCache) cached(kid string) (*rsa.PublicKey, bool) {
	if c.refresh <= 0 {
		return nil, false
	}
	if c.keys == nil || time.Since(c.lastFetch) >= c.refresh {
		return nil, false
	}
	pub, ok := c.keys[kid]
	return pub, ok
}

func (c *jwksCache) getKey(kid string) (*rsa.PublicKey, error) {
	c.mu.RLock()
	if pub, ok := c.cached(kid); ok {
		c.mu.RUnlock()
		return pub, nil
	}
	c.mu.RUnlock()

	c.mu.Lock()
	defer c.mu.Unlock()

	// Double-check after acquiring write lock.
	if pub, ok := c.cached(kid); ok {
		return pub, nil
	}

	keys, err := c.fetch()
	if err != nil {
		// On fetch error, fall back to the existing cache if we have one.
		if c.keys != nil {
			if pub, ok := c.keys[kid]; ok {
				return pub, nil
			}
		}
		return nil, err
	}
	c.keys = keys
	c.lastFetch = time.Now()

	pub, ok := keys[kid]
	if !ok {
		return nil, fmt.Errorf("JWKS does not contain key %q", kid)
	}
	return pub, nil
}

func (c *jwksCache) fetch() (map[string]*rsa.PublicKey, error) {
	resp, err := c.client.Get(c.url)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch JWKS: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("JWKS endpoint returned status %d", resp.StatusCode)
	}
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read JWKS response: %w", err)
	}
	return parseJWKSKeys(data)
}

func (pm *PermissionManager) Load() error {
	data, err := os.ReadFile(pm.configPath)
	if err != nil {
		return fmt.Errorf("failed to read permissions file: %w", err)
	}

	var raw map[string]yaml.Node
	if err := yaml.Unmarshal(data, &raw); err != nil {
		return fmt.Errorf("failed to parse permissions file: %w", err)
	}

	pm.mu.Lock()
	defer pm.mu.Unlock()

	pm.permissions = make(map[string][]string)
	pm.namespacePermissions = make(map[string][]string)

	for key, node := range raw {
		switch key {
		case "admin_users":
			if err := node.Decode(&pm.admins); err != nil {
				return fmt.Errorf("failed to parse admin list: %w", err)
			}
		case "user_permissions":
			var userNode map[string]yaml.Node
			if err := node.Decode(&userNode); err != nil {
				return fmt.Errorf("failed to parse user permissions: %w", err)
			}
			for userKey, userVal := range userNode {
				var patterns []string
				if err := userVal.Decode(&patterns); err != nil {
					return fmt.Errorf("failed to parse permissions for %s: %w", userKey, err)
				}
				pm.permissions[userKey] = patterns
			}
		case "namespace_permissions":
			if err := node.Decode(&pm.namespacePermissions); err != nil {
				return fmt.Errorf("failed to parse namespace permissions: %w", err)
			}
		default:
			return fmt.Errorf("unknown top-level key %q in permissions file", key)
		}
	}

	return nil
}

// Watch observes the permissions file using fsnotify (inotify on Linux) and
// reloads the configuration whenever it changes. It runs until the provided
// context is cancelled. Errors during reload are logged but do not stop the
// watcher.
//
// The watch is placed on the configured file path itself. This correctly
// handles both regular filesystem edits and Kubernetes ConfigMap/Secret
// volumes, where kubelet updates files by swapping the symlink target behind
// the user-visible file. In the Kubernetes case the old file is deleted,
// producing a Remove event, so the watch is re-established on the new target
// before reloading.
func (pm *PermissionManager) Watch(ctx context.Context, logger *slog.Logger) error {
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		return fmt.Errorf("failed to create fsnotify watcher: %w", err)
	}
	defer watcher.Close()

	addWatch := func() error {
		if err := watcher.Add(pm.configPath); err != nil {
			return fmt.Errorf("failed to watch permissions file %q: %w", pm.configPath, err)
		}
		return nil
	}

	if err := addWatch(); err != nil {
		return err
	}

	logger.Info("Watching permissions file for changes", "path", pm.configPath)

	const debounce = 100 * time.Millisecond
	reloadTimer := time.NewTimer(0)
	<-reloadTimer.C
	defer reloadTimer.Stop()

	resetReloadTimer := func() {
		if !reloadTimer.Stop() {
			select {
			case <-reloadTimer.C:
			default:
			}
		}
		reloadTimer.Reset(debounce)
	}

	for {
		select {
		case <-ctx.Done():
			return nil
		case event, ok := <-watcher.Events:
			if !ok {
				return errors.New("permissions watcher event channel closed")
			}
			// Kubernetes ConfigMap/Secret volumes update a file by replacing the
			// real file behind a symlink, which surfaces as a Remove (or Rename)
			// event on the watched path. The inotify watch is tied to the old
			// inode, so it must be re-established on the new file before we can
			// keep watching.
			if event.Has(fsnotify.Remove) || event.Has(fsnotify.Rename) {
				_ = watcher.Remove(pm.configPath)
				if err := addWatch(); err != nil {
					logger.Error("Failed to re-establish permissions watch", "error", err)
					continue
				}
				resetReloadTimer()
				continue
			}
			if !event.Has(fsnotify.Write) && !event.Has(fsnotify.Create) && !event.Has(fsnotify.Chmod) {
				continue
			}
			resetReloadTimer()
		case err, ok := <-watcher.Errors:
			if !ok {
				return errors.New("permissions watcher error channel closed")
			}
			logger.Error("Permissions watcher error", "error", err)
		case <-reloadTimer.C:
			if err := pm.Load(); err != nil {
				logger.Error("Failed to reload permissions", "error", err)
			} else {
				logger.Info("Permissions reloaded", "path", pm.configPath)
			}
		}
	}
}

func (pm *PermissionManager) ValidateJWT(tokenString string) (string, error) {
	token, err := jwt.Parse(tokenString, pm.keyfunc)
	if err != nil {
		return "", err
	}
	if !token.Valid {
		return "", errors.New("invalid token")
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return "", errors.New("invalid claims")
	}

	if pm.audience != "" && !audienceMatches(claims, pm.audience) {
		return "", fmt.Errorf("invalid audience; expected %s", pm.audience)
	}
	if pm.issuer != "" && !issuerMatches(claims, pm.issuer) {
		return "", fmt.Errorf("invalid issuer; expected %s", pm.issuer)
	}

	username, ok := claims[pm.userClaim].(string)
	if !ok || username == "" {
		return "", fmt.Errorf("claim %s not found or empty", pm.userClaim)
	}

	return username, nil
}

func audienceMatches(claims jwt.MapClaims, expected string) bool {
	raw, ok := claims["aud"]
	if !ok {
		return false
	}
	switch v := raw.(type) {
	case string:
		return v == expected
	case []string:
		for _, s := range v {
			if s == expected {
				return true
			}
		}
		return false
	case []interface{}:
		for _, s := range v {
			if str, ok := s.(string); ok && str == expected {
				return true
			}
		}
		return false
	}
	return false
}

func issuerMatches(claims jwt.MapClaims, expected string) bool {
	raw, ok := claims["iss"].(string)
	if !ok {
		return false
	}
	return raw == expected
}

func (pm *PermissionManager) GetUserPermissions(username string) *UserPermissions {
	pm.mu.RLock()
	defer pm.mu.RUnlock()

	up := &UserPermissions{
		username: username,
	}

	for _, admin := range pm.admins {
		if admin == username {
			up.isAdmin = true
			break
		}
	}

	if patterns, ok := pm.permissions[username]; ok {
		up.patterns = append([]string(nil), patterns...)
	}

	return up
}

func (up *UserPermissions) CanRead(vaultPath string) bool {
	if up.isAdmin {
		return true
	}
	for _, pattern := range up.patterns {
		if matchPermission(pattern, vaultPath) {
			return true
		}
	}
	return false
}

func (up *UserPermissions) CanWrite(vaultPath string) bool {
	return up.CanRead(vaultPath)
}

func (up *UserPermissions) CanExport() bool {
	return up.isAdmin
}

func matchPermission(pattern, vaultPath string) bool {
	pattern = normalizePath(pattern)
	vaultPath = normalizePath(vaultPath)

	if strings.HasSuffix(pattern, "/*") {
		prefix := strings.TrimSuffix(pattern, "/*")
		if prefix == "" {
			return true
		}
		if vaultPath == prefix {
			return true
		}
		if !strings.HasSuffix(prefix, "/") {
			prefix += "/"
		}
		return strings.HasPrefix(vaultPath, prefix)
	}

	return pattern == vaultPath
}

func (pm *PermissionManager) CanAccess(namespace, sa, vaultPath string) bool {
	if pm == nil {
		return true
	}

	pm.mu.RLock()
	defer pm.mu.RUnlock()

	key := namespace + "/" + sa
	if patterns, ok := pm.namespacePermissions[key]; ok {
		for _, pattern := range patterns {
			if matchPermission(pattern, vaultPath) {
				return true
			}
		}
		return false
	}

	if patterns, ok := pm.namespacePermissions[namespace]; ok {
		for _, pattern := range patterns {
			if matchPermission(pattern, vaultPath) {
				return true
			}
		}
		return false
	}

	return false
}
