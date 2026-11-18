package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"math/rand/v2"
	"time"
)

// Auto-unlock retry tuning. These are variables rather than constants so tests
// can compress the schedule.
var (
	// autoUnlockAttemptTimeout bounds a single attempt: the cloud KMS call plus
	// the Kubernetes API call that verifies the key against the stored vault.
	// Both can be slow on a node that just booted.
	autoUnlockAttemptTimeout = 10 * time.Second
	// autoUnlockInitialBackoff is the delay after the first failed attempt.
	autoUnlockInitialBackoff = 2 * time.Second
	// autoUnlockMaxBackoff caps the delay for transient failures: network not
	// ready yet, API server unreachable, KMS throttling.
	autoUnlockMaxBackoff = 60 * time.Second
	// autoUnlockRejectedBackoff is the delay used when the fetched key is
	// unusable (malformed, or not a recipient of the stored vault). Retrying
	// cannot fix a rotated key, so the delay stays long to keep KMS call volume
	// low while still recovering automatically once the key material is fixed.
	autoUnlockRejectedBackoff = 5 * time.Minute
)

// AutoUnlock keeps trying to unlock the vault with the configured key provider
// until it succeeds or ctx is cancelled, then returns nil.
//
// A single attempt at startup is not enough: right after a node reboots the
// Kubernetes API (and the cloud KMS endpoint) can be unreachable for tens of
// seconds, and a node that stays locked refuses every secret mount. Retrying
// with jittered backoff turns that transient outage into a short delay instead
// of a node that needs manual intervention.
func (m *VaultManager) AutoUnlock(ctx context.Context, logger *slog.Logger) error {
	if m.keyProvider == nil || !m.IsLocked() {
		return nil
	}

	backoff := autoUnlockInitialBackoff
	for attempt := 1; ; attempt++ {
		err := m.tryAutoUnlock(ctx)
		switch {
		case err == nil:
			logger.Info("Vault auto-unlocked via key provider", "attempts", attempt)
			return nil
		case errors.Is(err, ErrVaultAlreadyUnlocked):
			// Unlocked concurrently, e.g. through the Web UI.
			return nil
		case ctx.Err() != nil:
			return nil
		case errors.Is(err, ErrNoMasterKeyConfigured):
			logger.Info("No master key available from the key provider; vault stays locked until a manual unlock")
			return nil
		}

		wait := backoff
		if isVaultKeyError(err) {
			wait = autoUnlockRejectedBackoff
			logger.Error("Vault auto-unlock rejected the master key; retrying slowly",
				"attempt", attempt, "error", err, "retry_in", wait)
		} else {
			backoff = min(backoff*2, autoUnlockMaxBackoff)
			logger.Warn("Vault auto-unlock failed; retrying",
				"attempt", attempt, "error", err, "retry_in", wait)
		}

		timer := time.NewTimer(jitter(wait))
		select {
		case <-ctx.Done():
			timer.Stop()
			return nil
		case <-m.unlockKick:
			// A mount was refused: retry now rather than waiting out the backoff.
			timer.Stop()
		case <-timer.C:
		}
	}
}

// tryAutoUnlock performs one auto-unlock attempt: fetch the master key from the
// provider, then verify it against the stored vault before accepting it.
func (m *VaultManager) tryAutoUnlock(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, autoUnlockAttemptTimeout)
	defer cancel()

	key, err := m.keyProvider.GetMasterKey(ctx)
	if err != nil {
		return fmt.Errorf("failed to fetch master key: %w", err)
	}
	if key == "" {
		return &vaultKeyError{errors.New("key provider returned an empty master key")}
	}
	return m.Unlock(ctx, key)
}

// KickUnlock asks the auto-unlock loop to retry immediately instead of waiting
// for its backoff timer. It never blocks and is a no-op when no loop is running.
// Mount calls it so the kubelet's own retry drives recovery.
func (m *VaultManager) KickUnlock() {
	select {
	case m.unlockKick <- struct{}{}:
	default:
	}
}

// jitter spreads a delay by ±20% so a fleet of nodes that rebooted together
// does not hit the KMS and the API server in lockstep.
func jitter(d time.Duration) time.Duration {
	if d <= 0 {
		return 0
	}
	delta := int64(d) / 5
	if delta == 0 {
		return d
	}
	return d + time.Duration(rand.Int64N(2*delta+1)-delta)
}
