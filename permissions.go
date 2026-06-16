package main

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"

	"github.com/golang-jwt/jwt/v5"
	"gopkg.in/yaml.v3"
)

type PermissionManager struct {
	configPath string
	publicKey  *rsa.PublicKey
	userClaim  string

	mu          sync.RWMutex
	permissions map[string][]string
	admins      []string
}

// UserPermissions holds the resolved permissions for a single user.
type UserPermissions struct {
	username string
	isAdmin  bool
	patterns []string
}

func NewPermissionManager(configPath, publicKeyPEM, userClaim string) (*PermissionManager, error) {
	if configPath == "" {
		return nil, errors.New("config path is required")
	}
	if publicKeyPEM == "" {
		return nil, errors.New("JWT public key is required")
	}
	if userClaim == "" {
		userClaim = "sub"
	}

	pubKey, err := parseRSAPublicKey(publicKeyPEM)
	if err != nil {
		return nil, fmt.Errorf("failed to parse JWT public key: %w", err)
	}

	pm := &PermissionManager{
		configPath: configPath,
		publicKey:  pubKey,
		userClaim:  userClaim,
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

func (pm *PermissionManager) Load() error {
	data, err := os.ReadFile(pm.configPath)
	if err != nil {
		return fmt.Errorf("failed to read permissions file: %w", err)
	}

	var raw map[string][]string
	if err := yaml.Unmarshal(data, &raw); err != nil {
		return fmt.Errorf("failed to parse permissions file: %w", err)
	}

	pm.mu.Lock()
	defer pm.mu.Unlock()

	pm.permissions = make(map[string][]string)
	for key, val := range raw {
		if key == "admin" {
			pm.admins = val
			continue
		}
		pm.permissions[key] = val
	}

	return nil
}

func (pm *PermissionManager) ValidateJWT(tokenString string) (string, error) {
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return pm.publicKey, nil
	})
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

	username, ok := claims[pm.userClaim].(string)
	if !ok || username == "" {
		return "", fmt.Errorf("claim %s not found or empty", pm.userClaim)
	}

	return username, nil
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
