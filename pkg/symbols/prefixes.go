package symbols

import "strings"

// Symbol enrichment prefixes added by ipsw when annotating symbols.
const (
	PrefixStubHelper   = "__stub_helper."
	PrefixStubFallback = "__stub_"
	PrefixGot          = "__got."
	PrefixGotFallback  = "__got_"
	PrefixJump         = "j_"
	PrefixPointer      = "_ptr."
)

// EnrichmentPrefixes lists the canonical prefixes ipsw may prepend to an
// existing symbol name for additional context. Order matters: longer prefixes
// must appear before their shorter counterparts to ensure stable stripping.
var EnrichmentPrefixes = []string{
	PrefixStubHelper,
	PrefixStubFallback,
	PrefixGot,
	PrefixGotFallback,
	PrefixJump,
	PrefixPointer,
}

// StripEnrichmentPrefixes removes all known enrichment prefixes from name,
// returning the stripped symbol and the prefixes in the order they were removed.
func StripEnrichmentPrefixes(name string) (core string, prefixes []string) {
	core = name
trimLoop:
	for {
		for _, prefix := range EnrichmentPrefixes {
			if strings.HasPrefix(core, prefix) {
				prefixes = append(prefixes, prefix)
				core = strings.TrimPrefix(core, prefix)
				continue trimLoop
			}
		}
		break
	}
	return core, prefixes
}

// ApplyEnrichmentPrefixes re-applies prefixes (in the order returned by
// StripEnrichmentPrefixes) to base symbol text.
func ApplyEnrichmentPrefixes(prefixes []string, base string) string {
	out := base
	for i := len(prefixes) - 1; i >= 0; i-- {
		out = prefixes[i] + out
	}
	return out
}

// HasEnrichmentPrefix reports whether the symbol begins with a known enrichment prefix.
func HasEnrichmentPrefix(name string) bool {
	for _, prefix := range EnrichmentPrefixes {
		if strings.HasPrefix(name, prefix) {
			return true
		}
	}
	return false
}
