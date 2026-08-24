package download

import (
	"fmt"
	"net/url"
	"strings"
	"sync"

	godl "github.com/blacktop/go-download"
)

const (
	// DefaultParts is the Generic and Apple CDN connection cap (the
	// engine's own default).
	DefaultParts = godl.DefaultParts
	// DefaultMinParts is the Generic eager connection floor. This is an
	// ipsw profile choice: the engine's own floor default is 1.
	DefaultMinParts = 4
	// DefaultMinPartSize is the Generic scheduler split floor (the
	// engine's own default).
	DefaultMinPartSize = godl.DefaultMinPartSize
	// AppleCDNMinParts disables aggregate ramping for known per-flow-limited
	// Apple CDN workloads.
	AppleCDNMinParts = 8
	// AppleCDNMinPartSize is the Apple CDN scheduler split floor.
	AppleCDNMinPartSize int64 = 8 << 20
	// AuthenticatedAppleMinParts intentionally matches AppleCDNMinParts until
	// paired benchmark evidence supports changing the authenticated default.
	AuthenticatedAppleMinParts = AppleCDNMinParts
	// AuthenticatedAppleMinPartSize intentionally matches AppleCDNMinPartSize
	// under the same evidence requirement.
	AuthenticatedAppleMinPartSize = AppleCDNMinPartSize
	// MaxParts bounds overrides so a typo cannot open thousands of sockets.
	MaxParts = 64
)

// Profile identifies the workload defaults selected before final-host
// classification. A parseable non-Apple final hostname demotes the workload to
// GenericProfile; a URL without a parseable hostname retains the normalized
// workload.
type Profile uint8

const (
	GenericProfile Profile = iota
	AppleCDNProfile
	// AuthenticatedAppleProfile identifies Developer Portal, ADC, and App Store
	// workloads.
	AuthenticatedAppleProfile
)

// EnginePolicy is one fully resolved go-download engine tuple. It is the
// engine's own Concurrency type: EnableNodeSelection is not part of it —
// placement is a construction-time engine setting kept on PolicyOverrides.
type EnginePolicy = godl.Concurrency

// PolicyOverrides contains process-wide CLI/config overrides. Integer zero
// means use the selected URL profile's value. Parts=1 resolves to the
// single-stream 1/1 mode; MinPartSize remains the user's explicit value when
// supplied and otherwise inherits the selected URL profile.
type PolicyOverrides struct {
	Parts               int
	MinParts            int
	MinPartSize         int64
	EnableNodeSelection bool
}

var (
	policyMu        sync.RWMutex
	policyOverrides PolicyOverrides
)

// SetPolicyOverrides validates and installs process-wide download overrides.
func SetPolicyOverrides(overrides PolicyOverrides) error {
	if overrides.Parts < 0 || overrides.Parts > MaxParts {
		return fmt.Errorf("parts must be 0 or satisfy 1 <= parts <= %d, got %d",
			MaxParts, overrides.Parts)
	}
	if overrides.MinParts < 0 || overrides.MinParts > MaxParts {
		return fmt.Errorf("min-parts must be 0 or satisfy 1 <= min-parts <= %d, got %d",
			MaxParts, overrides.MinParts)
	}
	if overrides.MinPartSize < 0 {
		return fmt.Errorf("min-part-size must be >= 0, got %d", overrides.MinPartSize)
	}
	if overrides.MinParts != 0 {
		parts := overrides.Parts
		if parts == 0 {
			parts = DefaultParts
		}
		if overrides.MinParts > parts {
			return fmt.Errorf("min-parts must satisfy 1 <= min-parts <= parts (%d), got %d",
				parts, overrides.MinParts)
		}
	}
	policyMu.Lock()
	policyOverrides = overrides
	policyMu.Unlock()
	return nil
}

// GetPolicyOverrides returns the current process-wide download overrides.
func GetPolicyOverrides() PolicyOverrides {
	policyMu.RLock()
	defer policyMu.RUnlock()
	return policyOverrides
}

// ResolvePolicy classifies rawURL within the selected workload and applies the
// current overrides.
// Overrides are validated by SetPolicyOverrides, so resolution is infallible.
func ResolvePolicy(rawURL string, workload Profile) EnginePolicy {
	return resolveProfile(profileForURL(rawURL, workload), GetPolicyOverrides())
}

func resolveProfile(profile Profile, overrides PolicyOverrides) EnginePolicy {
	policy := EnginePolicy{
		Parts: DefaultParts, MinParts: DefaultMinParts, MinPartSize: DefaultMinPartSize,
	}
	switch profile {
	case AppleCDNProfile:
		policy.MinParts = AppleCDNMinParts
		policy.MinPartSize = AppleCDNMinPartSize
	case AuthenticatedAppleProfile:
		policy.MinParts = AuthenticatedAppleMinParts
		policy.MinPartSize = AuthenticatedAppleMinPartSize
	case GenericProfile:
		// Keep the Generic defaults above.
	default:
		// Unknown profiles fail closed to the Generic tuple.
	}
	if overrides.Parts != 0 {
		policy.Parts = overrides.Parts
	}
	if overrides.MinParts != 0 {
		policy.MinParts = overrides.MinParts
	} else if policy.MinParts > policy.Parts {
		policy.MinParts = policy.Parts
	}
	if overrides.MinPartSize != 0 {
		policy.MinPartSize = overrides.MinPartSize
	}
	return policy
}

func profileForURL(rawURL string, workload Profile) Profile {
	workload = normalizedProfile(workload)
	u, err := url.Parse(rawURL)
	if err != nil || u.Opaque != "" {
		return workload
	}
	host := godl.NormalizeHost(u.Hostname())
	if host == "" {
		return workload
	}
	if !isAppleDownloadHost(host) {
		return GenericProfile
	}
	if workload == AuthenticatedAppleProfile {
		return AuthenticatedAppleProfile
	}
	return AppleCDNProfile
}

func normalizedProfile(profile Profile) Profile {
	switch profile {
	case GenericProfile, AppleCDNProfile, AuthenticatedAppleProfile:
		return profile
	default:
		return GenericProfile
	}
}

func isAppleDownloadHost(host string) bool {
	for _, domain := range []string{"cdn-apple.com", "apple.com", "aaplimg.com", "mzstatic.com"} {
		if host == domain || strings.HasSuffix(host, "."+domain) {
			return true
		}
	}
	return false
}
