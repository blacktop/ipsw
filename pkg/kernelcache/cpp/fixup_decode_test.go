package cpp

import (
	"testing"

	"github.com/blacktop/go-macho/pkg/fixupchains"
)

// kcRebaseSlot describes the auth/rebase fields of a
// DYLD_CHAINED_PTR_64_KERNEL_CACHE slot (modern MH_FILESET kernelcache).
type kcRebaseSlot struct {
	target     uint64 // bits [0,30)
	cacheLevel uint64 // bits [30,32)
	diversity  uint64 // bits [32,48)
	addrDiv    uint64 // bit  48
	key        uint64 // bits [49,51)
	next       uint64 // bits [51,63)
	auth       bool   // bit  63
}

// encKCRebaseSlot packs a DyldChainedPtr64KernelCacheRebase raw pointer word.
func encKCRebaseSlot(s kcRebaseSlot) uint64 {
	raw := s.target & ((1 << 30) - 1)
	raw |= (s.cacheLevel & 0x3) << 30
	raw |= (s.diversity & 0xffff) << 32
	raw |= (s.addrDiv & 0x1) << 48
	raw |= (s.key & 0x3) << 49
	raw |= (s.next & 0xfff) << 51
	if s.auth {
		raw |= 1 << 63
	}
	return raw
}

// arm64eAuthRebaseSlot describes a DYLD_CHAINED_PTR_ARM64E auth-rebase slot
// (older arm64e kernelcache). The concrete type is already the auth form.
type arm64eAuthRebaseSlot struct {
	target    uint64 // bits [0,32)
	diversity uint64 // bits [32,48)
	addrDiv   uint64 // bit  48
	key       uint64 // bits [49,51)
	next      uint64 // bits [51,62)
}

// encArm64eAuthRebaseSlot packs a DyldChainedPtrArm64eAuthRebase raw pointer
// word with bind=0 (rebase) and auth=1 (auth form).
func encArm64eAuthRebaseSlot(s arm64eAuthRebaseSlot) uint64 {
	raw := s.target & ((1 << 32) - 1)
	raw |= (s.diversity & 0xffff) << 32
	raw |= (s.addrDiv & 0x1) << 48
	raw |= (s.key & 0x3) << 49
	raw |= (s.next & 0x7ff) << 51
	raw |= 1 << 63 // auth
	return raw
}

func TestKernelCacheAuthRebaseSlotDecode(t *testing.T) {
	t.Parallel()

	auth := fixupchains.DyldChainedPtr64KernelCacheRebase{
		Fixup: 0x100,
		Pointer: encKCRebaseSlot(kcRebaseSlot{
			target: 0x1234, cacheLevel: 0, diversity: 0xabcd, addrDiv: 1, key: 2, next: 1, auth: true,
		}),
	}

	if auth.IsAuth() != 1 {
		t.Fatalf("IsAuth() = %d, want 1", auth.IsAuth())
	}
	if !auth.IsRebase() || auth.IsBind() {
		t.Fatalf("kcache slot should be a rebase (IsRebase=%v IsBind=%v)", auth.IsRebase(), auth.IsBind())
	}
	if auth.Diversity() != 0xabcd {
		t.Fatalf("Diversity() = %#x, want 0xabcd", auth.Diversity())
	}
	if auth.Key() != 2 {
		t.Fatalf("Key() = %d, want 2 (DA)", auth.Key())
	}
	if auth.AddrDiv() != 1 {
		t.Fatalf("AddrDiv() = %d, want 1", auth.AddrDiv())
	}
	if auth.Target() != 0x1234 {
		t.Fatalf("Target() = %#x, want 0x1234", auth.Target())
	}
	if auth.CacheLevel() != 0 {
		t.Fatalf("CacheLevel() = %d, want 0", auth.CacheLevel())
	}
}

func TestKernelCacheUnsignedSlotReportsNonAuth(t *testing.T) {
	t.Parallel()

	// An UNSIGNED kcache slot: auth=0 but the diversity bit-field still holds
	// non-zero bits. Diversity() therefore returns garbage; callers MUST gate on
	// the concrete IsAuth() before trusting it (see plan Phase 0 landmine).
	unsigned := fixupchains.DyldChainedPtr64KernelCacheRebase{
		Fixup: 0x108,
		Pointer: encKCRebaseSlot(kcRebaseSlot{
			target: 0x5678, cacheLevel: 1, diversity: 0x9999, key: 1, next: 1, auth: false,
		}),
	}

	if unsigned.IsAuth() != 0 {
		t.Fatalf("IsAuth() = %d, want 0 for an unsigned kcache slot", unsigned.IsAuth())
	}
	if unsigned.Target() != 0x5678 {
		t.Fatalf("Target() = %#x, want 0x5678", unsigned.Target())
	}
	if unsigned.CacheLevel() != 1 {
		t.Fatalf("CacheLevel() = %d, want 1", unsigned.CacheLevel())
	}
	if unsigned.Diversity() != 0x9999 {
		t.Fatalf("Diversity() = %#x, want 0x9999 garbage that gating on IsAuth must discard", unsigned.Diversity())
	}
}

func TestArm64eAuthRebaseSlotDecode(t *testing.T) {
	t.Parallel()

	auth := fixupchains.DyldChainedPtrArm64eAuthRebase{
		Fixup: 0x200,
		Pointer: encArm64eAuthRebaseSlot(arm64eAuthRebaseSlot{
			target: 0xdead, diversity: 0x1357, addrDiv: 1, key: 1, next: 2,
		}),
	}

	if auth.Auth() != 1 {
		t.Fatalf("Auth() = %d, want 1 (arm64e auth-rebase concrete form)", auth.Auth())
	}
	if !auth.IsRebase() || auth.IsBind() {
		t.Fatalf("arm64e auth slot should be a rebase (IsRebase=%v IsBind=%v)", auth.IsRebase(), auth.IsBind())
	}
	if auth.Diversity() != 0x1357 {
		t.Fatalf("Diversity() = %#x, want 0x1357", auth.Diversity())
	}
	if auth.Key() != 1 {
		t.Fatalf("Key() = %d, want 1 (IB)", auth.Key())
	}
	if auth.AddrDiv() != 1 {
		t.Fatalf("AddrDiv() = %d, want 1", auth.AddrDiv())
	}
	if auth.Target() != 0xdead {
		t.Fatalf("Target() = %#x, want 0xdead", auth.Target())
	}
}
