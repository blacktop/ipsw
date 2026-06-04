package storage

import (
	"bytes"
	"encoding/gob"
	"fmt"
	"maps"
	"sync"
)

// MemoryStore is the in-memory Store used for OTA/Directory diff modes, tests,
// and any run that does not need cross-invocation persistence. Values are gob
// encoded on Put and decoded on Get so the observable behavior matches
// SQLiteStore: Tasks always round-trip through the same serialization, and a
// MemoryStore cache hit cannot accidentally hand back a live struct that a
// SQLite hit would have decoded into a fresh allocation.
type MemoryStore struct {
	mu sync.RWMutex
	// rows is keyed by Scope, then by row key. The inner map is non-nil for
	// any Scope that has ever been written to.
	rows map[Scope]map[string][]byte
	// complete records which Scopes have been marked complete by their
	// owning Task.
	complete map[Scope]bool
}

// NewMemoryStore returns an empty in-memory Store. The zero value is not
// usable; callers must go through this constructor so the internal maps are
// allocated up front.
func NewMemoryStore() *MemoryStore {
	return &MemoryStore{
		rows:     make(map[Scope]map[string][]byte),
		complete: make(map[Scope]bool),
	}
}

// Put gob-encodes v and stores it under (scope, key), replacing any prior
// value.
func (s *MemoryStore) Put(scope Scope, key string, v any) error {
	var buf bytes.Buffer
	if err := gob.NewEncoder(&buf).Encode(v); err != nil {
		return fmt.Errorf("memory store: encode %s/%s: %w", scope.Task, key, err)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	bucket, ok := s.rows[scope]
	if !ok {
		bucket = make(map[string][]byte)
		s.rows[scope] = bucket
	}
	// Copy the encoded bytes so callers may reuse the input buffer freely.
	enc := make([]byte, buf.Len())
	copy(enc, buf.Bytes())
	bucket[key] = enc
	return nil
}

// Get loads the value at (scope, key) into v. found is false when no row
// exists; err is non-nil only on decode failures.
func (s *MemoryStore) Get(scope Scope, key string, v any) (bool, error) {
	s.mu.RLock()
	bucket, ok := s.rows[scope]
	if !ok {
		s.mu.RUnlock()
		return false, nil
	}
	enc, ok := bucket[key]
	s.mu.RUnlock()
	if !ok {
		return false, nil
	}
	if err := gob.NewDecoder(bytes.NewReader(enc)).Decode(v); err != nil {
		return true, fmt.Errorf("memory store: decode %s/%s: %w", scope.Task, key, err)
	}
	return true, nil
}

// Iter calls fn for every row in scope. Rows are visited under a snapshot
// taken with the read lock held, so fn may freely call back into the store.
func (s *MemoryStore) Iter(scope Scope, fn func(key string, decode func(v any) error) error) error {
	s.mu.RLock()
	bucket, ok := s.rows[scope]
	if !ok {
		s.mu.RUnlock()
		return nil
	}
	// Snapshot keys + payload pointers so fn may mutate the store via other
	// Scopes without deadlocking. Values are immutable byte slices.
	snapshot := make(map[string][]byte, len(bucket))
	maps.Copy(snapshot, bucket)
	s.mu.RUnlock()
	for k, enc := range snapshot {
		decode := func(v any) error {
			if err := gob.NewDecoder(bytes.NewReader(enc)).Decode(v); err != nil {
				return fmt.Errorf("memory store: decode %s/%s: %w", scope.Task, k, err)
			}
			return nil
		}
		if err := fn(k, decode); err != nil {
			return err
		}
	}
	return nil
}

// MarkComplete records that every required row for scope has been written.
func (s *MemoryStore) MarkComplete(scope Scope) error {
	s.mu.Lock()
	s.complete[scope] = true
	s.mu.Unlock()
	return nil
}

// Complete reports whether MarkComplete was previously called for scope.
func (s *MemoryStore) Complete(scope Scope) (bool, error) {
	s.mu.RLock()
	done := s.complete[scope]
	s.mu.RUnlock()
	return done, nil
}

// Close is a no-op for MemoryStore.
func (s *MemoryStore) Close() error { return nil }
