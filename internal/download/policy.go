package download

import (
	"fmt"
	"net/url"
	"strings"
	"sync"
)

const (
	// DefaultParts is the Generic and Apple CDN connection cap.
	DefaultParts = 8
	// DefaultMinParts is the Generic eager connection floor.
	DefaultMinParts = 4
	// DefaultMinPartSize is the Generic scheduler split floor.
	DefaultMinPartSize int64 = 16 << 20
	// AppleCDNMinParts disables aggregate ramping for known per-flow-limited
	// Apple CDN workloads.
	AppleCDNMinParts = 8
	// AppleCDNMinPartSize is the Apple CDN scheduler split floor.
	AppleCDNMinPartSize int64 = 8 << 20
	// MaxParts bounds overrides so a typo cannot open thousands of sockets.
	MaxParts = 64
)

// Profile selects workload defaults when a URL cannot classify itself.
type Profile uint8

const (
	GenericProfile Profile = iota
	AppleCDNProfile
)

// EnginePolicy is one fully resolved go-download engine tuple.
type EnginePolicy struct {
	Parts               int
	MinParts            int
	MinPartSize         int64
	EnableNodeSelection bool
}

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
	for _, profile := range []Profile{GenericProfile, AppleCDNProfile} {
		if _, err := resolveProfile(profile, overrides); err != nil {
			return err
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

// ResolvePolicy classifies rawURL and applies the current overrides.
func ResolvePolicy(rawURL string, fallback Profile) (EnginePolicy, error) {
	policyMu.RLock()
	overrides := policyOverrides
	policyMu.RUnlock()
	return resolveProfile(profileForURL(rawURL, fallback), overrides)
}

func resolveProfile(profile Profile, overrides PolicyOverrides) (EnginePolicy, error) {
	policy := EnginePolicy{
		Parts: DefaultParts, MinParts: DefaultMinParts, MinPartSize: DefaultMinPartSize,
		EnableNodeSelection: overrides.EnableNodeSelection,
	}
	if profile == AppleCDNProfile {
		policy.MinParts = AppleCDNMinParts
		policy.MinPartSize = AppleCDNMinPartSize
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
	if policy.MinParts < 1 || policy.MinParts > policy.Parts {
		return EnginePolicy{}, fmt.Errorf(
			"min-parts must satisfy 1 <= min-parts <= parts (%d), got %d",
			policy.Parts, policy.MinParts)
	}
	return policy, nil
}

// profilesConverge reports whether the current overrides pin every profile
// to one identical tuple, making URL classification (and therefore redirect
// resolution) unnecessary.
func profilesConverge() bool {
	overrides := GetPolicyOverrides()
	generic, gerr := resolveProfile(GenericProfile, overrides)
	apple, aerr := resolveProfile(AppleCDNProfile, overrides)
	return gerr == nil && aerr == nil && generic == apple
}

func profileForURL(rawURL string, fallback Profile) Profile {
	if fallback != AppleCDNProfile {
		fallback = GenericProfile
	}
	u, err := url.Parse(rawURL)
	if err != nil || u.Opaque != "" {
		return fallback
	}
	host := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(u.Hostname()), "."))
	if host == "" {
		return fallback
	}
	for _, domain := range []string{"cdn-apple.com", "apple.com", "aaplimg.com", "mzstatic.com"} {
		if host == domain || strings.HasSuffix(host, "."+domain) {
			return AppleCDNProfile
		}
	}
	return GenericProfile
}
