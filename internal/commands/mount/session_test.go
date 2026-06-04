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

func TestSessionReleaseUnmountsAndEvictsType(t *testing.T) {
	calls := map[string]int{}
	var unmounted []string
	s := newTestSession(func(typ string) (*Context, error) {
		calls[typ]++
		return &Context{MountPoint: "/mnt/" + typ}, nil
	}, &unmounted)

	if _, err := s.Root("fs"); err != nil {
		t.Fatalf("Root(fs): %v", err)
	}
	if err := s.Release("fs"); err != nil {
		t.Fatalf("Release(fs): %v", err)
	}
	if !slices.Equal(unmounted, []string{"/mnt/fs"}) {
		t.Fatalf("unmounted = %v, want /mnt/fs", unmounted)
	}
	if _, err := s.Root("fs"); err != nil {
		t.Fatalf("Root(fs) after release: %v", err)
	}
	if calls["fs"] != 2 {
		t.Fatalf("fs mounted %d times, want 2", calls["fs"])
	}
}

func TestSessionReleaseEvictsAliasedMounts(t *testing.T) {
	calls := map[string]int{}
	var unmounted []string
	s := newTestSession(func(typ string) (*Context, error) {
		calls[typ]++
		return &Context{MountPoint: "/mnt/shared"}, nil
	}, &unmounted)

	for _, typ := range []string{"sys", "fs"} {
		if _, err := s.Root(typ); err != nil {
			t.Fatalf("Root(%s): %v", typ, err)
		}
	}
	if err := s.Release("fs"); err != nil {
		t.Fatalf("Release(fs): %v", err)
	}
	if !slices.Equal(unmounted, []string{"/mnt/shared"}) {
		t.Fatalf("unmounted = %v, want shared mount once", unmounted)
	}
	if _, err := s.Root("sys"); err != nil {
		t.Fatalf("Root(sys) after alias release: %v", err)
	}
	if calls["sys"] != 2 {
		t.Fatalf("sys mounted %d times, want 2", calls["sys"])
	}
}

func TestSessionReleaseSkipsExternalMount(t *testing.T) {
	calls := map[string]int{}
	var unmounted []string
	s := newTestSession(func(typ string) (*Context, error) {
		calls[typ]++
		return &Context{MountPoint: "/mnt/" + typ, AlreadyMounted: true}, nil
	}, &unmounted)

	if _, err := s.Root("app"); err != nil {
		t.Fatalf("Root(app): %v", err)
	}
	if err := s.Release("app"); err != nil {
		t.Fatalf("Release(app): %v", err)
	}
	if len(unmounted) != 0 {
		t.Fatalf("unmounted = %v, want nothing for external mount", unmounted)
	}
	if _, err := s.Root("app"); err != nil {
		t.Fatalf("Root(app) after release: %v", err)
	}
	if calls["app"] != 2 {
		t.Fatalf("app mounted %d times, want 2", calls["app"])
	}
}

func TestSessionReleaseKeepsCacheOnUnmountError(t *testing.T) {
	want := errors.New("unmount failed")
	calls := map[string]int{}
	s := &Session{mounts: make(map[string]*Context)}
	s.mount = func(typ string) (*Context, error) {
		calls[typ]++
		return &Context{MountPoint: "/mnt/" + typ}, nil
	}
	s.unmount = func(*Context) error {
		return want
	}

	if _, err := s.Root("fs"); err != nil {
		t.Fatalf("Root(fs): %v", err)
	}
	if err := s.Release("fs"); !errors.Is(err, want) {
		t.Fatalf("Release(fs) error = %v, want %v", err, want)
	}
	if _, err := s.Root("fs"); err != nil {
		t.Fatalf("Root(fs) after failed release: %v", err)
	}
	if calls["fs"] != 1 {
		t.Fatalf("fs mounted %d times, want cached mount after failed release", calls["fs"])
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
