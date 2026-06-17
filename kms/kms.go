//go:build kms

package kms

import (
	"context"
	"encoding/base64"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/kms"
)

// Decryptor is a subset of the AWS KMS client interface, used for testability.
type Decryptor interface {
	Decrypt(ctx context.Context, params *kms.DecryptInput, optFns ...func(*kms.Options)) (*kms.DecryptOutput, error)
}

// Client wraps the AWS KMS SDK client and provides a method to fetch the age
// master key from an encrypted KMS ciphertext blob.
type Client struct {
	kms Decryptor
}

// NewClient creates a new KMS client using the default AWS configuration chain.
func NewClient(ctx context.Context) (*Client, error) {
	cfg, err := config.LoadDefaultConfig(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to load AWS config: %w", err)
	}
	return &Client{kms: kms.NewFromConfig(cfg)}, nil
}

// NewClientWithDecryptor creates a KMS client with a custom Decryptor (useful for testing).
func NewClientWithDecryptor(d Decryptor) *Client {
	return &Client{kms: d}
}

// GetAgeKey decrypts a base64-encoded KMS ciphertext blob and returns the
// plaintext age identity (master key) as a string.
func (c *Client) GetAgeKey(ctx context.Context, ciphertextB64 string) (string, error) {
	ct, err := base64.StdEncoding.DecodeString(ciphertextB64)
	if err != nil {
		return "", fmt.Errorf("failed to decode KMS ciphertext: %w", err)
	}

	result, err := c.kms.Decrypt(ctx, &kms.DecryptInput{
		CiphertextBlob: ct,
	})
	if err != nil {
		return "", fmt.Errorf("AWS KMS decrypt failed: %w", err)
	}

	if result.Plaintext == nil || len(result.Plaintext) == 0 {
		return "", fmt.Errorf("AWS KMS decrypt returned empty plaintext")
	}

	return string(result.Plaintext), nil
}
