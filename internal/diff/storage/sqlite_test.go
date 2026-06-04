package storage

import (
	"path/filepath"
	"sort"
	"sync"
	"testing"
)

func newTestSQLiteStore(t *testing.T) *SQLiteStore {
	t.Helper()
	path := filepath.Join(t.TempDir(), "diff.db")
	s, err := NewSQLiteStore(path)
	if err != nil {
		t.Fatalf("NewSQLiteStore: %v", err)
	}
	t.Cleanup(func() {
		if err := s.Close(); err != nil {
			t.Errorf("Close: %v", err)
		}
	})
	return s
}

func TestSQLiteStorePutGetRoundTrip(t *testing.T) {
	s := newTestSQLiteStore(t)
	scope := baseScope()
	want := payload{Path: "/usr/lib/libSystem.B.dylib", Count: 42}
	if err := s.Put(scope, "row-1", want); err != nil {
		t.Fatalf("Put: %v", err)
	}
	var got payload
	found, err := s.Get(scope, "row-1", &got)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if !found {
		t.Fatalf("Get: expected found=true")
	}
	if got != want {
		t.Fatalf("Get: got %+v, want %+v", got, want)
	}

	// Re-Put under the same key should overwrite without error.
	want2 := payload{Path: "/usr/lib/libSystem.B.dylib", Count: 99}
	if err := s.Put(scope, "row-1", want2); err != nil {
		t.Fatalf("Put (overwrite): %v", err)
	}
	var got2 payload
	if _, err := s.Get(scope, "row-1", &got2); err != nil {
		t.Fatalf("Get (overwrite): %v", err)
	}
	if got2 != want2 {
		t.Fatalf("Get (overwrite): got %+v, want %+v", got2, want2)
	}

	// Missing key returns found=false, no error.
	found, err = s.Get(scope, "missing", &got)
	if err != nil {
		t.Fatalf("Get(missing): %v", err)
	}
	if found {
		t.Fatalf("Get(missing): expected found=false")
	}
}

func TestSQLiteStoreIter(t *testing.T) {
	s := newTestSQLiteStore(t)
	scope := baseScope()
	keys := []string{"a", "b", "c"}
	for _, k := range keys {
		if err := s.Put(scope, k, payload{Path: k, Count: len(k)}); err != nil {
			t.Fatalf("Put(%s): %v", k, err)
		}
	}
	other := scope
	other.Task = "other"
	if err := s.Put(other, "z", payload{Path: "z"}); err != nil {
		t.Fatalf("Put(other): %v", err)
	}

	seen := make(map[string]payload)
	if err := s.Iter(scope, func(k string, decode func(any) error) error {
		var p payload
		if err := decode(&p); err != nil {
			return err
		}
		seen[k] = p
		return nil
	}); err != nil {
		t.Fatalf("Iter: %v", err)
	}
	if got, want := len(seen), len(keys); got != want {
		seenKeys := make([]string, 0, len(seen))
		for k := range seen {
			seenKeys = append(seenKeys, k)
		}
		sort.Strings(seenKeys)
		t.Fatalf("Iter: got %d keys (%v), want %d (%v)", got, seenKeys, want, keys)
	}
	for _, k := range keys {
		got, ok := seen[k]
		if !ok {
			t.Fatalf("Iter: missing key %q", k)
		}
		if want := (payload{Path: k, Count: len(k)}); got != want {
			t.Fatalf("Iter[%s]: got %+v, want %+v", k, got, want)
		}
	}
}

func TestSQLiteStoreMarkComplete(t *testing.T) {
	s := newTestSQLiteStore(t)
	scope := baseScope()

	done, err := s.Complete(scope)
	if err != nil {
		t.Fatalf("Complete (initial): %v", err)
	}
	if done {
		t.Fatalf("Complete (initial): want false")
	}
	if err := s.MarkComplete(scope); err != nil {
		t.Fatalf("MarkComplete: %v", err)
	}
	done, err = s.Complete(scope)
	if err != nil {
		t.Fatalf("Complete: %v", err)
	}
	if !done {
		t.Fatalf("Complete: want true after MarkComplete")
	}
	// Re-marking the same scope must not error or duplicate.
	if err := s.MarkComplete(scope); err != nil {
		t.Fatalf("MarkComplete (repeat): %v", err)
	}
}

func TestSQLiteStoreScopeMismatch(t *testing.T) {
	s := newTestSQLiteStore(t)
	scope := baseScope()
	if err := s.Put(scope, "k", payload{Path: "p"}); err != nil {
		t.Fatalf("Put: %v", err)
	}
	if err := s.MarkComplete(scope); err != nil {
		t.Fatalf("MarkComplete: %v", err)
	}

	cases := []struct {
		name   string
		mutate func(*Scope)
	}{
		{"TaskVersion", func(sc *Scope) { sc.TaskVersion = 2 }},
		{"OptionsHash", func(sc *Scope) { sc.OptionsHash = "opts-b" }},
		{"InputHash", func(sc *Scope) { sc.InputHash = "input-b" }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			alt := scope
			tc.mutate(&alt)
			var got payload
			found, err := s.Get(alt, "k", &got)
			if err != nil {
				t.Fatalf("Get(%s): %v", tc.name, err)
			}
			if found {
				t.Fatalf("Get(%s): expected found=false on scope mismatch", tc.name)
			}
			done, err := s.Complete(alt)
			if err != nil {
				t.Fatalf("Complete(%s): %v", tc.name, err)
			}
			if done {
				t.Fatalf("Complete(%s): expected false on scope mismatch", tc.name)
			}
		})
	}
}

func TestSQLiteStoreCreatesParentDirs(t *testing.T) {
	path := filepath.Join(t.TempDir(), "nested", "sub", "diff.db")
	s, err := NewSQLiteStore(path)
	if err != nil {
		t.Fatalf("NewSQLiteStore: %v", err)
	}
	if err := s.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
}

// TestSQLiteStorePutAfterClose covers the closed-vs-writeCh race: concurrent
// Put/MarkComplete must observe the closed state via the RWMutex instead of
// sending on a closed channel and panicking.
func TestSQLiteStorePutAfterClose(t *testing.T) {
	path := filepath.Join(t.TempDir(), "diff.db")
	s, err := NewSQLiteStore(path)
	if err != nil {
		t.Fatalf("NewSQLiteStore: %v", err)
	}
	scope := baseScope()

	var wg sync.WaitGroup
	start := make(chan struct{})
	const writers = 8
	wg.Add(writers)
	for i := range writers {
		go func(i int) {
			defer wg.Done()
			<-start
			_ = s.Put(scope, "k", payload{Path: "p", Count: i})
			_ = s.MarkComplete(scope)
		}(i)
	}
	close(start)
	if err := s.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	wg.Wait()

	// Post-Close calls must report the closed sentinel, not panic.
	if err := s.Put(scope, "k", payload{Path: "p"}); err == nil {
		t.Fatal("Put after Close: expected error, got nil")
	}
	if err := s.MarkComplete(scope); err == nil {
		t.Fatal("MarkComplete after Close: expected error, got nil")
	}
}

func TestSQLiteStoreCloseIdempotent(t *testing.T) {
	path := filepath.Join(t.TempDir(), "diff.db")
	s, err := NewSQLiteStore(path)
	if err != nil {
		t.Fatalf("NewSQLiteStore: %v", err)
	}
	if err := s.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if err := s.Close(); err != nil {
		t.Fatalf("Close (second): %v", err)
	}
}
