package workloadkeyapi

import (
	"context"
	"crypto"
	"errors"
	"io"
	"time"
)

var ErrCapabilityExpired = errors.New("opaque key capability is expired")

type OperationMode uint8

const (
	LocalReferenceMode OperationMode = iota + 1
	RemoteSignMode
)

func (m OperationMode) String() string {
	switch m {
	case LocalReferenceMode:
		return "local_reference"
	case RemoteSignMode:
		return "remote_sign"
	default:
		return "unsupported"
	}
}

func (m OperationMode) Supported() bool {
	return m == LocalReferenceMode || m == RemoteSignMode
}

type Capability struct {
	ID         []byte
	Generation uint64
	PublicKey  crypto.PublicKey
	Mode       OperationMode
	Binding    string
	ExpiresAt  time.Time
}

type SignRequest struct {
	CapabilityID []byte
	Generation   uint64
	Digest       []byte
	Hash         crypto.Hash
	Binding      string
}

type SignClient interface {
	Sign(context.Context, SignRequest) ([]byte, error)
}

type SignClientFunc func(context.Context, SignRequest) ([]byte, error)

func (f SignClientFunc) Sign(ctx context.Context, request SignRequest) ([]byte, error) {
	return f(ctx, request)
}

type RPCSigner struct {
	client     SignClient
	capability Capability
	now        func() time.Time
}

func NewRPCSigner(client SignClient, capability Capability) (*RPCSigner, error) {
	if client == nil || len(capability.ID) == 0 || capability.Generation == 0 ||
		capability.PublicKey == nil || capability.Mode != RemoteSignMode ||
		capability.Binding == "" || capability.ExpiresAt.IsZero() {
		return nil, errors.New("invalid opaque key capability")
	}
	return &RPCSigner{client: client, capability: capability, now: time.Now}, nil
}

func (s *RPCSigner) Public() crypto.PublicKey {
	return s.capability.PublicKey
}

func (s *RPCSigner) Sign(_ io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	if !s.now().Before(s.capability.ExpiresAt) {
		return nil, ErrCapabilityExpired
	}
	if opts == nil || opts.HashFunc() != crypto.SHA256 || len(digest) != crypto.SHA256.Size() {
		return nil, errors.New("only SHA-256 digests are accepted")
	}
	return s.client.Sign(context.Background(), SignRequest{
		CapabilityID: append([]byte(nil), s.capability.ID...),
		Generation:   s.capability.Generation,
		Digest:       append([]byte(nil), digest...),
		Hash:         opts.HashFunc(),
		Binding:      s.capability.Binding,
	})
}
