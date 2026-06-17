//go:build kms

package kms

import (
	"context"
	"encoding/base64"
	"testing"

	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type mockDecryptor struct {
	plaintext []byte
	err       error
}

func (m *mockDecryptor) Decrypt(ctx context.Context, params *kms.DecryptInput, optFns ...func(*kms.Options)) (*kms.DecryptOutput, error) {
	if m.err != nil {
		return nil, m.err
	}
	return &kms.DecryptOutput{Plaintext: m.plaintext}, nil
}

func TestGetAgeKey_Success(t *testing.T) {
	mock := &mockDecryptor{plaintext: []byte("AGE-SECRET-KEY-1TESTKEY1234")}
	client := NewClientWithDecryptor(mock)
	ct := base64.StdEncoding.EncodeToString([]byte("encrypted-blob"))

	key, err := client.GetAgeKey(context.Background(), ct)
	require.NoError(t, err)
	assert.Equal(t, "AGE-SECRET-KEY-1TESTKEY1234", key)
}

func TestGetAgeKey_InvalidBase64(t *testing.T) {
	client := NewClientWithDecryptor(&mockDecryptor{})

	_, err := client.GetAgeKey(context.Background(), "!!!not-base64!!!")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to decode KMS ciphertext")
}

func TestGetAgeKey_DecryptError(t *testing.T) {
	mock := &mockDecryptor{err: assert.AnError}
	client := NewClientWithDecryptor(mock)

	_, err := client.GetAgeKey(context.Background(), base64.StdEncoding.EncodeToString([]byte("blob")))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "AWS KMS decrypt failed")
}

func TestGetAgeKey_EmptyPlaintext(t *testing.T) {
	mock := &mockDecryptor{plaintext: nil}
	client := NewClientWithDecryptor(mock)

	_, err := client.GetAgeKey(context.Background(), base64.StdEncoding.EncodeToString([]byte("blob")))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "empty plaintext")
}
