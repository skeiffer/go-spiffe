package workloadkeyapi_test

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"io"
	"testing"

	"github.com/spiffe/go-spiffe/v2/svid/x509svid"
	"github.com/spiffe/go-spiffe/v2/workloadkeyapi"
	"github.com/stretchr/testify/require"
)

type fakeSigner struct {
	key   *rsa.PrivateKey
	calls int
}

func newFakeSigner(t *testing.T) *fakeSigner {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	return &fakeSigner{key: key}
}

func (s *fakeSigner) Public() crypto.PublicKey {
	return &s.key.PublicKey
}

func (s *fakeSigner) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	s.calls++
	return s.key.Sign(rand, digest, opts)
}

func TestSourceExposesGenericCryptoSignerWithoutPrivateKeySerialization(t *testing.T) {
	signer := newFakeSigner(t)
	source, err := workloadkeyapi.NewSource(workloadkeyapi.Update{
		SVID:       &x509svid.SVID{PrivateKey: signer},
		Generation: 1,
	})
	require.NoError(t, err)

	svid, err := source.GetX509SVID()
	require.NoError(t, err)
	digest := sha256.Sum256([]byte("contract-test"))
	_, err = svid.PrivateKey.Sign(rand.Reader, digest[:], crypto.SHA256)
	require.NoError(t, err)
	require.Equal(t, 1, signer.calls)
}

func TestSourceRotatesOnlyToNewerGeneration(t *testing.T) {
	first := newFakeSigner(t)
	next := newFakeSigner(t)
	source, err := workloadkeyapi.NewSource(workloadkeyapi.Update{
		SVID:       &x509svid.SVID{PrivateKey: first},
		Generation: 4,
	})
	require.NoError(t, err)

	require.EqualError(t, source.Apply(workloadkeyapi.Update{
		SVID:       &x509svid.SVID{PrivateKey: next},
		Generation: 4,
	}), "key-backed SVID generation must increase")
	require.NoError(t, source.Apply(workloadkeyapi.Update{
		SVID:       &x509svid.SVID{PrivateKey: next},
		Generation: 5,
	}))
	require.Equal(t, uint64(5), source.Generation())
	svid, err := source.GetX509SVID()
	require.NoError(t, err)
	require.Same(t, next, svid.PrivateKey)
}

func TestOpaqueRequiredNeverInvokesStandardFallback(t *testing.T) {
	called := false
	_, err := workloadkeyapi.RequireOpaque(func() (*x509svid.SVID, error) {
		called = true
		return &x509svid.SVID{}, nil
	})
	require.ErrorIs(t, err, workloadkeyapi.ErrOpaqueDowngrade)
	require.False(t, called)
}
