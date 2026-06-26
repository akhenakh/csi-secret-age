package main

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestTokenCacheKey(t *testing.T) {
	// Deterministic for the same token.
	require.Equal(t, tokenCacheKey("abc"), tokenCacheKey("abc"))
	// Distinct tokens hash to distinct keys.
	require.NotEqual(t, tokenCacheKey("abc"), tokenCacheKey("abd"))
	// The raw token never appears in the key.
	require.NotContains(t, tokenCacheKey("super-secret-token"), "super-secret-token")
}

func TestUserInfoCache_HitAndExpiry(t *testing.T) {
	c := newUserInfoCache(time.Minute)

	_, ok := c.get("k")
	require.False(t, ok, "empty cache must miss")

	c.put("k", "alice@example.com")
	got, ok := c.get("k")
	require.True(t, ok)
	assert.Equal(t, "alice@example.com", got)
}

func TestUserInfoCache_Expires(t *testing.T) {
	c := newUserInfoCache(5 * time.Millisecond)
	c.put("k", "bob@example.com")

	time.Sleep(15 * time.Millisecond)

	_, ok := c.get("k")
	assert.False(t, ok, "entry must expire after its TTL")
}

func TestUserInfoCache_DefaultsTTL(t *testing.T) {
	// Non-positive TTL falls back to a sane default rather than expiring instantly.
	c := newUserInfoCache(0)
	require.Equal(t, 5*time.Minute, c.ttl)
}

func TestValidateAccessToken_NotConfigured(t *testing.T) {
	pm := &PermissionManager{}
	_, err := pm.ValidateAccessToken(t.Context(), "token")
	require.Error(t, err, "must error when UserInfo validation is not enabled")
}
