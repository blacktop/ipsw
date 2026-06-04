package mount

import (
	"errors"
	"sync"
)

// Session lazily mounts DMGs from a single IPSW and keeps them mounted for the
// session's lifetime, so multiple consumers can share one mount per DMG instead
// of each mounting (and re-extracting/re-decrypting) the same DMG.
//
// Each requested DMG type is mounted at most once; Close unmounts everything the
// session mounted and removes the extracted backing files, exactly once. A
// Session is safe for concurrent use.
type Session struct {
	ipswPath string
	cfg      Config

	mu     sync.Mutex
	mounts map[string]*Context // dmg type ("sys"/"fs"/"app"/"exc"/"rdisk") -> mount

	// seams for testing; default to the real mount/unmount primitives.
	mount   func(typ string) (*Context, error)
	unmount func(*Context) error
}

// NewSession creates a Session for the given IPSW. cfg may be nil.
func NewSession(ipswPath string, cfg *Config) *Session {
	var c Config
	if cfg != nil {
		c = *cfg
	}
	s := &Session{
		ipswPath: ipswPath,
		cfg:      c,
		mounts:   make(map[string]*Context),
	}
	s.mount = func(typ string) (*Context, error) {
		return DmgInIPSW(s.ipswPath, typ, &s.cfg)
	}
	s.unmount = func(ctx *Context) error {
		return ctx.Unmount()
	}
	return s
}

// Root mounts the DMG of the given type (one of DmgTypes) if it is not already
// mounted by this session, and returns its mount point. Repeated calls for the
// same type return the cached mount without re-mounting.
func (s *Session) Root(typ string) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if ctx, ok := s.mounts[typ]; ok {
		return ctx.MountPoint, nil
	}
	ctx, err := s.mount(typ)
	if err != nil {
		return "", err
	}
	s.mounts[typ] = ctx
	return ctx.MountPoint, nil
}

// Release unmounts the DMG backing typ and removes it from the session cache.
// Any cached type aliases that resolved to the same mount point are evicted too,
// so a later Root call for any of them will mount again. DMGs that were already
// mounted before the session acquired them (AlreadyMounted) are only evicted.
func (s *Session) Release(typ string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	ctx, ok := s.mounts[typ]
	if !ok {
		return nil
	}

	return s.releaseMountPointLocked(ctx.MountPoint)
}

func (s *Session) releaseMountPointLocked(mountPoint string) error {
	var aliases []string
	var owner *Context
	for typ, ctx := range s.mounts {
		if ctx.MountPoint != mountPoint {
			continue
		}
		aliases = append(aliases, typ)
		if owner == nil && !ctx.AlreadyMounted {
			owner = ctx
		}
	}
	if len(aliases) == 0 {
		return nil
	}
	if owner != nil {
		if err := s.unmount(owner); err != nil {
			return err
		}
	}
	for _, typ := range aliases {
		delete(s.mounts, typ)
	}
	return nil
}

// Close unmounts every DMG this session mounted and removes the extracted
// backing files. DMGs that were already mounted before the session acquired
// them (AlreadyMounted) are left in place, and DMGs that resolved to the same
// mount point (e.g. "sys" falling back to "fs" on pre-cryptex IPSWs) are
// unmounted only once. It is safe to call Close more than once.
func (s *Session) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	seen := make(map[string]bool, len(s.mounts))
	var errs []error
	for _, ctx := range s.mounts {
		if ctx.AlreadyMounted || seen[ctx.MountPoint] {
			continue
		}
		seen[ctx.MountPoint] = true
		if err := s.unmount(ctx); err != nil {
			errs = append(errs, err)
		}
	}
	s.mounts = make(map[string]*Context)
	return errors.Join(errs...)
}
