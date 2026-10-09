package workloadkeyapi

import (
	"errors"
	"sync"

	"github.com/spiffe/go-spiffe/v2/svid/x509svid"
)

var ErrOpaqueDowngrade = errors.New("opaque key delivery required; standard Workload API fallback is disabled")

type Update struct {
	SVID       *x509svid.SVID
	Generation uint64
}

type Source struct {
	mu     sync.RWMutex
	update Update
}

func NewSource(initial Update) (*Source, error) {
	if initial.SVID == nil || initial.SVID.PrivateKey == nil {
		return nil, errors.New("key-backed SVID requires a crypto.Signer")
	}
	return &Source{update: initial}, nil
}

func (s *Source) GetX509SVID() (*x509svid.SVID, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.update.SVID, nil
}

func (s *Source) Generation() uint64 {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.update.Generation
}

func (s *Source) Apply(update Update) error {
	if update.SVID == nil || update.SVID.PrivateKey == nil {
		return errors.New("key-backed SVID requires a crypto.Signer")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if update.Generation <= s.update.Generation {
		return errors.New("key-backed SVID generation must increase")
	}
	s.update = update
	return nil
}

func RequireOpaque(standardFallback func() (*x509svid.SVID, error)) (*x509svid.SVID, error) {
	_ = standardFallback
	return nil, ErrOpaqueDowngrade
}
