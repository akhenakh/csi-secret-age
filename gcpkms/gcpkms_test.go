//go:build gcpkms

package gcpkms

import (
	"context"
	"encoding/base64"
	"errors"
	"testing"

	"cloud.google.com/go/kms/apiv1/kmspb"
	"github.com/googleapis/gax-go/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type mockDecryptor struct {
	plaintext []byte
	err       error
}

func (m *mockDecryptor) Decrypt(ctx context.Context, req *kmspb.DecryptRequest, opts ...gax.CallOption) (*kmspb.DecryptResponse, error) {
	if m.err != nil {
		return nil, m.err
	}
	return &kmspb.DecryptResponse{Plaintext: m.plaintext}, nil
}

func (m *mockDecryptor) Close() error {
	return nil
}

func TestGetAgeKey_Success(t *testing.T) {
	mock := &mockDecryptor{plaintext: []byte("AGE-SECRET-KEY-1GCPTESTKEY")}
	client := NewClientWithDecryptor(mock, "projects/p/locations/global/keyRings/kr/cryptoKeys/ck")
	ct := base64.StdEncoding.EncodeToString([]byte("encrypted-blob"))

	key, err := client.GetAgeKey(context.Background(), ct)
	require.NoError(t, err)
	assert.Equal(t, "AGE-SECRET-KEY-1GCPTESTKEY", key)
}

func TestGetAgeKey_InvalidBase64(t *testing.T) {
	client := NewClientWithDecryptor(&mockDecryptor{}, "projects/p/locations/global/keyRings/kr/cryptoKeys/ck")

	_, err := client.GetAgeKey(context.Background(), "!!!not-base64!!!")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to decode GCP KMS ciphertext")
}

func TestGetAgeKey_DecryptError(t *testing.T) {
	mock := &mockDecryptor{err: errors.New("permission denied")}
	client := NewClientWithDecryptor(mock, "projects/p/locations/global/keyRings/kr/cryptoKeys/ck")

	_, err := client.GetAgeKey(context.Background(), base64.StdEncoding.EncodeToString([]byte("blob")))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "GCP KMS decrypt failed")
}

func TestGetAgeKey_EmptyPlaintext(t *testing.T) {
	mock := &mockDecryptor{plaintext: nil}
	client := NewClientWithDecryptor(mock, "projects/p/locations/global/keyRings/kr/cryptoKeys/ck")

	_, err := client.GetAgeKey(context.Background(), base64.StdEncoding.EncodeToString([]byte("blob")))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "empty plaintext")
}
