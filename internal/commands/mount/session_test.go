package mount

import (
	"errors"
	"slices"
	"testing"
)

// newTestSession returns a Session whose mount/unmount are backed by fakes so
// the caching and cleanup logic can be exercised without real DMGs.
func newTestSession(mountFn func(string) (*Context, error), unmounted *[]string) *Session {
	s := &Session{mounts: make(map[string]*Context)}
	s.mount = mountFn
	s.unmount = func(ctx *Context) error {
		*unmounted = append(*unmounted, ctx.MountPoint)
		return nil
	}
	return s
}

func TestSessionRootMountsOncePerType(t *testing.T) {
	calls := map[string]int{}
	var unmounted []string
	s := newTestSession(func(typ string) (*Context, error) {
		calls[typ]++
		return &Context{MountPoint: "/mnt/" + typ}, nil
	}, &unmounted)

	for range 3 {
		mp, err := s.Root("sys")
		if err != nil {
			t.Fatalf("Root(sys): %v", err)
		}
		if mp != "/mnt/sys" {
			t.Fatalf("mount point = %q, want /mnt/sys", mp)
		}
	}
	if _, err := s.Root("fs"); err != nil {
		t.Fatalf("Root(fs): %v", err)
	}

	if calls["sys"] != 1 {
		t.Errorf("sys mounted %d times, want 1", calls["sys"])
	}
	if calls["fs"] != 1 {
		t.Errorf("fs mounted %d times, want 1", calls["fs"])
	}

	if err := s.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	slices.Sort(unmounted)
	if !slices.Equal(unmounted, []string{"/mnt/fs", "/mnt/sys"}) {
		t.Errorf("unmounted = %v, want each distinct mount once", unmounted)
	}
}

func TestSessionCloseDedupsAliasedMountsAndSkipsExternal(t *testing.T) {
	var unmounted []string
	s := newTestSession(func(typ string) (*Context, error) {
		switch typ {
		case "sys", "fs":
			// Pre-cryptex IPSW: "sys" falls back to the same DMG as "fs".
			return &Context{MountPoint: "/mnt/shared"}, nil
		case "app":
			// Pre-existing mount owned by someone else; must not be unmounted.
			return &Context{MountPoint: "/mnt/app", AlreadyMounted: true}, nil
		default:
			return &Context{MountPoint: "/mnt/" + typ}, nil
		}
	}, &unmounted)

	for _, typ := range []string{"sys", "fs", "app"} {
		if _, err := s.Root(typ); err != nil {
			t.Fatalf("Root(%s): %v", typ, err)
		}
	}

	if err := s.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if !slices.Equal(unmounted, []string{"/mnt/shared"}) {
		t.Errorf("unmounted = %v, want only /mnt/shared once (alias deduped, external skipped)", unmounted)
	}
}

func TestSessionRootPropagatesMountError(t *testing.T) {
	want := errors.New("boom")
	var unmounted []string
	s := newTestSession(func(string) (*Context, error) {
		return nil, want
	}, &unmounted)

	if _, err := s.Root("exc"); !errors.Is(err, want) {
		t.Fatalf("Root error = %v, want %v", err, want)
	}
	if err := s.Close(); err != nil {
		t.Fatalf("Close after failed mount: %v", err)
	}
	if len(unmounted) != 0 {
		t.Errorf("unmounted = %v, want nothing (mount failed)", unmounted)
	}
}
