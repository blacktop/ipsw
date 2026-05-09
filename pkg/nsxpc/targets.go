package nsxpc

import (
	"strings"

	"github.com/blacktop/ipsw/pkg/symbols"
)

const (
	selInterfaceWithProtocol = "interfaceWithProtocol:"
	selSetClasses            = "setClasses:forSelector:argumentIndex:ofReply:"
	selDecodeObjectOfClass   = "decodeObjectOfClass:forKey:"
	selDecodeObjectOfClasses = "decodeObjectOfClasses:forKey:"
	selSetWithObject         = "setWithObject:"
	selSetWithObjects        = "setWithObjects:"
	selArrayWithObjects      = "arrayWithObjects:"
)

type targetKind uint8

const (
	targetObjCMessage targetKind = iota + 1
	targetObjCGetClass
	targetObjCGetProtocol
)

type targetSpec struct {
	Kind     targetKind
	Selector string
	Name     string
}

func relevantSelectors() map[string]struct{} {
	return map[string]struct{}{
		selInterfaceWithProtocol: {},
		selSetClasses:            {},
		selDecodeObjectOfClass:   {},
		selDecodeObjectOfClasses: {},
		selSetWithObject:         {},
		selSetWithObjects:        {},
		selArrayWithObjects:      {},
		"initWithCoder:":         {},
	}
}

func isNSXPCSelector(selector string) bool {
	switch selector {
	case selInterfaceWithProtocol, selSetClasses:
		return true
	default:
		return false
	}
}

func matchRuntimeTarget(symbolName string) (targetSpec, bool) {
	clean, demangled := symbolCandidates(symbolName)
	base := strings.TrimSuffix(clean, "_stub")
	switch base {
	case "objc_msgSend":
		return targetSpec{Kind: targetObjCMessage, Name: base}, true
	case "objc_getClass", "objc_lookUpClass", "objc_getRequiredClass", "objc_opt_class":
		return targetSpec{Kind: targetObjCGetClass, Name: base}, true
	case "objc_getProtocol":
		return targetSpec{Kind: targetObjCGetProtocol, Name: base}, true
	}
	for _, prefix := range []string{"objc_msgSend$", "objc_msgSendSuper2$"} {
		if after, ok := strings.CutPrefix(base, prefix); ok {
			sel := after
			if _, ok := relevantSelectors()[sel]; ok {
				return targetSpec{Kind: targetObjCMessage, Selector: sel, Name: base}, true
			}
		}
	}
	if strings.Contains(demangled, "objc_msgSend(") {
		return targetSpec{Kind: targetObjCMessage, Name: base}, true
	}
	return targetSpec{}, false
}

func targetForObjCStubSelector(selector string) (targetSpec, bool) {
	if _, ok := relevantSelectors()[selector]; !ok {
		return targetSpec{}, false
	}
	return targetSpec{Kind: targetObjCMessage, Selector: selector, Name: "objc_msgSend$" + selector}, true
}

func symbolCandidates(name string) (string, string) {
	clean := strings.TrimSpace(name)
	clean = strings.TrimPrefix(clean, "j_")
	clean = strings.TrimPrefix(clean, "__")
	clean = strings.TrimPrefix(clean, "_")
	if idx := strings.Index(clean, " ; "); idx >= 0 {
		clean = clean[:idx]
	}
	return clean, symbols.DemangleBareSymbol(clean)
}
