package storage

import (
	"sort"
	"testing"
)

type payload struct {
	Path  string
	Count int
}

func baseScope() Scope {
	return Scope{
		IpswOld:     "old.ipsw",
		IpswNew:     "new.ipsw",
		Task:        "machos",
		TaskVersion: 1,
		OptionsHash: "opts-a",
		InputHash:   "input-a",
	}
}

func TestMemoryStorePutGetRoundTrip(t *testing.T) {
	s := NewMemoryStore()
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

	// Missing key returns found=false, no error.
	found, err = s.Get(scope, "missing", &got)
	if err != nil {
		t.Fatalf("Get(missing): %v", err)
	}
	if found {
		t.Fatalf("Get(missing): expected found=false")
	}
}

func TestMemoryStoreIter(t *testing.T) {
	s := NewMemoryStore()
	scope := baseScope()
	keys := []string{"a", "b", "c"}
	for _, k := range keys {
		if err := s.Put(scope, k, payload{Path: k, Count: len(k)}); err != nil {
			t.Fatalf("Put(%s): %v", k, err)
		}
	}
	// Also write to a different scope; Iter must ignore it.
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

func TestMemoryStoreMarkComplete(t *testing.T) {
	s := NewMemoryStore()
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
}

func TestMemoryStoreScopeMismatch(t *testing.T) {
	s := NewMemoryStore()
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

func TestMemoryStoreClose(t *testing.T) {
	s := NewMemoryStore()
	if err := s.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
}
