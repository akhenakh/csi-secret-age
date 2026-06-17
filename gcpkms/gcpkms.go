//go:build gcpkms

package gcpkms

import (
	"context"
	"encoding/base64"
	"fmt"

	kms "cloud.google.com/go/kms/apiv1"
	"cloud.google.com/go/kms/apiv1/kmspb"
	"github.com/googleapis/gax-go/v2"
)

// Decryptor is a subset of the GCP KMS KeyManagementClient, used for testability.
type Decryptor interface {
	Decrypt(ctx context.Context, req *kmspb.DecryptRequest, opts ...gax.CallOption) (*kmspb.DecryptResponse, error)
	Close() error
}

// Client wraps the GCP KMS KeyManagementClient and provides a method to fetch
// the age master key from an encrypted ciphertext blob.
type Client struct {
	kms      Decryptor
	keyName  string
}

// NewClient creates a new GCP KMS client using default application credentials.
func NewClient(ctx context.Context, keyName string) (*Client, error) {
	c, err := kms.NewKeyManagementClient(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCP KMS client: %w", err)
	}
	return &Client{kms: c, keyName: keyName}, nil
}

// NewClientWithDecryptor creates a GCP KMS client with a custom Decryptor (useful for testing).
func NewClientWithDecryptor(d Decryptor, keyName string) *Client {
	return &Client{kms: d, keyName: keyName}
}

// Close releases resources held by the underlying GCP KMS client.
func (c *Client) Close() error {
	return c.kms.Close()
}

// GetAgeKey decrypts a base64-encoded GCP KMS ciphertext blob and returns the
// plaintext age identity (master key) as a string.
func (c *Client) GetAgeKey(ctx context.Context, ciphertextB64 string) (string, error) {
	ct, err := base64.StdEncoding.DecodeString(ciphertextB64)
	if err != nil {
		return "", fmt.Errorf("failed to decode GCP KMS ciphertext: %w", err)
	}

	resp, err := c.kms.Decrypt(ctx, &kmspb.DecryptRequest{
		Name:       c.keyName,
		Ciphertext: ct,
	})
	if err != nil {
		return "", fmt.Errorf("GCP KMS decrypt failed: %w", err)
	}

	if resp.Plaintext == nil || len(resp.Plaintext) == 0 {
		return "", fmt.Errorf("GCP KMS decrypt returned empty plaintext")
	}

	return string(resp.Plaintext), nil
}
