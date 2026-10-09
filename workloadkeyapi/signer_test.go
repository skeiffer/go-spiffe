package workloadkeyapi_test

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"testing"
	"time"

	"github.com/spiffe/go-spiffe/v2/workloadkeyapi"
	"github.com/stretchr/testify/require"
)

func TestRPCSignerReauthorizesEverySignAndRejectsExpiredCapability(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	calls := 0
	client := workloadkeyapi.SignClientFunc(func(_ context.Context, request workloadkeyapi.SignRequest) ([]byte, error) {
		calls++
		require.Equal(t, "process-binding", request.Binding)
		return rsa.SignPKCS1v15(rand.Reader, key, request.Hash, request.Digest)
	})
	signer, err := workloadkeyapi.NewRPCSigner(client, workloadkeyapi.Capability{
		ID:         []byte("capability"),
		Generation: 4,
		PublicKey:  &key.PublicKey,
		Mode:       workloadkeyapi.RemoteSignMode,
		Binding:    "process-binding",
		ExpiresAt:  time.Now().Add(time.Minute),
	})
	require.NoError(t, err)

	digest := sha256.Sum256([]byte("rpc-signer"))
	signature, err := signer.Sign(rand.Reader, digest[:], crypto.SHA256)
	require.NoError(t, err)
	require.NoError(t, rsa.VerifyPKCS1v15(&key.PublicKey, crypto.SHA256, digest[:], signature))
	require.Equal(t, 1, calls)

	expired, err := workloadkeyapi.NewRPCSigner(client, workloadkeyapi.Capability{
		ID:         []byte("expired"),
		Generation: 5,
		PublicKey:  &key.PublicKey,
		Mode:       workloadkeyapi.RemoteSignMode,
		Binding:    "process-binding",
		ExpiresAt:  time.Now().Add(-time.Second),
	})
	require.NoError(t, err)
	_, err = expired.Sign(rand.Reader, digest[:], crypto.SHA256)
	require.ErrorIs(t, err, workloadkeyapi.ErrCapabilityExpired)
	require.Equal(t, 1, calls)
}

func TestNeutralOperationModes(t *testing.T) {
	require.Equal(t, "local_reference", workloadkeyapi.LocalReferenceMode.String())
	require.Equal(t, "remote_sign", workloadkeyapi.RemoteSignMode.String())
	require.False(t, workloadkeyapi.OperationMode(0).Supported())
}
