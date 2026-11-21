// Package store implements the admission policy store.
package store

import (
	"strings"
	"sync/atomic"
	"time"

	"github.com/example/cluster-admission-guard/internal/admission"
	"github.com/example/cluster-admission-guard/internal/policy"
)

// Loaded is an immutable snapshot of policy state.
type Loaded struct {
	Policies   []*policy.CompiledPolicy
	TrustStore *policy.TrustStore
	// Errors are problems that occurred while loading. Non-empty means the
	// snapshot is the last known good one but the source is currently broken.
	Errors   []error
	LoadedAt time.Time
	Source   string
}

// SnapshotStore is an in-memory, atomically-swappable admission.Store. It is
// the building block for the file and cluster stores and is used directly by
// tests.
type SnapshotStore struct {
	current   atomic.Pointer[Loaded]
	nsResolve func(string) (policy.NamespaceInfo, bool)
}

// NewSnapshotStore builds a store with an initial snapshot.
func NewSnapshotStore(initial *Loaded) *SnapshotStore {
	s := &SnapshotStore{}
	if initial == nil {
		initial = &Loaded{LoadedAt: time.Now()}
	}
	s.current.Store(initial)
	return s
}

// SetNamespaceResolver overrides how namespace metadata is read.
func (s *SnapshotStore) SetNamespaceResolver(fn func(string) (policy.NamespaceInfo, bool)) {
	s.nsResolve = fn
}

// Swap atomically installs a new snapshot.
func (s *SnapshotStore) Swap(l *Loaded) {
	if l.LoadedAt.IsZero() {
		l.LoadedAt = time.Now()
	}
	s.current.Store(l)
}

// Current returns the active snapshot.
func (s *SnapshotStore) Current() *Loaded { return s.current.Load() }

// Policies implements admission.Store.
func (s *SnapshotStore) Policies() []*policy.CompiledPolicy {
	if l := s.current.Load(); l != nil {
		return l.Policies
	}
	return nil
}

// TrustStore implements admission.Store.
func (s *SnapshotStore) TrustStore() *policy.TrustStore {
	if l := s.current.Load(); l != nil {
		return l.TrustStore
	}
	return nil
}

// Namespace implements admission.Store.
func (s *SnapshotStore) Namespace(name string) (policy.NamespaceInfo, bool) {
	if s.nsResolve != nil {
		return s.nsResolve(name)
	}
	return policy.NamespaceInfo{}, false
}

// Health implements admission.Store.
func (s *SnapshotStore) Health() error {
	l := s.current.Load()
	if l == nil {
		return errNotInitialized
	}
	if len(l.Errors) > 0 {
		msgs := make([]string, 0, len(l.Errors))
		for _, e := range l.Errors {
			msgs = append(msgs, e.Error())
		}
		return &healthError{msg: strings.Join(msgs, "; ")}
	}
	return nil
}

func (s *SnapshotStore) setErrors(status string) {}

type healthError struct{ msg string }

func (e *healthError) Error() string { return e.msg }

var errNotInitialized = &healthError{msg: "policy store not initialized"}

var _ admission.Store = (*SnapshotStore)(nil)
