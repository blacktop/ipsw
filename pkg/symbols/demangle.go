package symbols

import (
	"regexp"
	"strings"

	"github.com/blacktop/go-macho/pkg/swift"
	"github.com/blacktop/ipsw/internal/demangle"
)

var (
	cxxTokenPattern = regexp.MustCompile(`_{0,2}Z[A-Za-z0-9_]+`)
)

// demangleCoreSymbol runs the Swift and C++ demanglers against a core symbol.
func demangleCoreSymbol(name string) string {
	out := swift.DemangleBlob(name)

	out = cxxTokenPattern.ReplaceAllStringFunc(out, func(token string) string {
		// Normalize bare Z to _Z:
		// some symbols (notably .cold.N functions
		// from hot/cold code splitting) appear without the conventional
		// underscore prefix, remaining mangled.
		// Example from kernelcache:
		//		ZN18AppleMobileApNonce5startEP9IOService.cold.1
		if token[0] == 'Z' {
		    token = "_" + token
		}

		if demangled := demangle.Do(token, false, false); demangled != token {
			return demangled
		}
		if strings.HasPrefix(token, "_Z") {
			if demangled := demangle.Do("_"+token, false, false); demangled != "_"+token {
				return demangled
			}
		}
		return token
	})

	return out
}

// DemangleSymbolName attempts to demangle Swift and C++ tokens inside a symbol string.
// It preserves any contextual prefixes/suffixes like stub helpers while expanding
// the mangled portion for readability.
func DemangleSymbolName(name string) string {
	if name == "" {
		return name
	}
	core, prefixes := StripEnrichmentPrefixes(name)
	demangled := demangleCoreSymbol(core)
	return ApplyEnrichmentPrefixes(prefixes, demangled)
}

// DemangleBareSymbol exposes the demangling of a core symbol without prefix handling.
func DemangleBareSymbol(name string) string {
	return demangleCoreSymbol(name)
}

// FormatSymbol returns a display-friendly version of name, applying demangling
// and falling back to showing the underlying target when the decorated form
// cannot be demangled.
func FormatSymbol(name string, demangle bool) string {
	if !demangle {
		return name
	}
	demangled := DemangleSymbolName(name)
	if demangled != name {
		return demangled
	}
	core, prefixes := StripEnrichmentPrefixes(name)
	if len(prefixes) == 0 || core == "" {
		return name
	}
	coreDemangled := demangleCoreSymbol(core)
	if coreDemangled == core {
		return name
	}
	return name + " (target: " + coreDemangled + ")"
}
