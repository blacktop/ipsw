package xrefs

import (
	"strings"

	"github.com/blacktop/ipsw/pkg/symbols"
)

type Source string

const (
	SourceKernelcache Source = "kernelcache"
	SourceDSC         Source = "dsc"
)

type targetSpec struct {
	Source      Source
	Canonical   string
	Aliases     []string
	KeyReg      int
	ValueReg    int
	SelectorReg int
	Selector    string
	KeyArray    bool
	Discovery   string
	VirtualSlot int
}

func (t targetSpec) hasValue() bool {
	return t.ValueReg >= 0
}

func objcValueForEntitlementTarget() targetSpec {
	return targetSpec{
		Source:    SourceDSC,
		Canonical: "-[NSXPCConnection valueForEntitlement:]",
		Aliases:   []string{"objc_msgSend$valueForEntitlement:"},
		KeyReg:    2,
		ValueReg:  -1,
	}
}

var kernelTargetSpecs = []targetSpec{
	{Source: SourceKernelcache, Canonical: "IOTaskHasEntitlement", Aliases: []string{"IOTaskHasEntitlement"}, KeyReg: 1, ValueReg: -1},
	{Source: SourceKernelcache, Canonical: "IOCurrentTaskHasEntitlement", Aliases: []string{"IOCurrentTaskHasEntitlement"}, KeyReg: 0, ValueReg: -1},
	{Source: SourceKernelcache, Canonical: "IOTaskHasStringEntitlement", Aliases: []string{"IOTaskHasStringEntitlement"}, KeyReg: 1, ValueReg: 2},
	{Source: SourceKernelcache, Canonical: "IOUserClient::copyClientEntitlement", Aliases: []string{"IOUserClient::copyClientEntitlement", "copyClientEntitlement"}, KeyReg: 1, ValueReg: -1},
	{Source: SourceKernelcache, Canonical: "IOUserClient::copyClientEntitlementVnode", Aliases: []string{"IOUserClient::copyClientEntitlementVnode", "copyClientEntitlementVnode"}, KeyReg: 2, ValueReg: -1},
	{Source: SourceKernelcache, Canonical: "IOUserClient::clientHasPrivilege", Aliases: []string{"IOUserClient::clientHasPrivilege", "clientHasPrivilege"}, KeyReg: 1, ValueReg: -1},
	{Source: SourceKernelcache, Canonical: "csproc_get_platform_binary_entitlement", Aliases: []string{"csproc_get_platform_binary_entitlement"}, KeyReg: 1, ValueReg: -1},
}

func kernelTargets() []targetSpec {
	return kernelTargetSpecs
}

var dscTargetSpecs = []targetSpec{
	{Source: SourceDSC, Canonical: "xpc_connection_copy_entitlement_value", Aliases: []string{"xpc_connection_copy_entitlement_value"}, KeyReg: 1, ValueReg: -1},
	{Source: SourceDSC, Canonical: "xpc_connection_has_entitlement", Aliases: []string{"xpc_connection_has_entitlement"}, KeyReg: 1, ValueReg: -1},
	{Source: SourceDSC, Canonical: "xpc_connection_set_peer_entitlement_exists_requirement", Aliases: []string{"xpc_connection_set_peer_entitlement_exists_requirement"}, KeyReg: 1, ValueReg: -1},
	{Source: SourceDSC, Canonical: "xpc_connection_set_peer_entitlement_matches_value_requirement", Aliases: []string{"xpc_connection_set_peer_entitlement_matches_value_requirement"}, KeyReg: 1, ValueReg: 2},
	{Source: SourceDSC, Canonical: "xpc_connection_set_lwcr_entitlement_requirement", Aliases: []string{"xpc_connection_set_lwcr_entitlement_requirement"}, KeyReg: 1, ValueReg: -1},
	{Source: SourceDSC, Canonical: "xpc_copy_entitlement_for_token", Aliases: []string{"xpc_copy_entitlement_for_token"}, KeyReg: 1, ValueReg: -1},
	{Source: SourceDSC, Canonical: "SecTaskCopyValueForEntitlement", Aliases: []string{"SecTaskCopyValueForEntitlement"}, KeyReg: 1, ValueReg: -1},
	{Source: SourceDSC, Canonical: "SecTaskCopyValuesForEntitlements", Aliases: []string{"SecTaskCopyValuesForEntitlements"}, KeyReg: 1, ValueReg: -1, KeyArray: true},
	{Source: SourceDSC, Canonical: "SecTaskGetBooleanValueForEntitlement", Aliases: []string{"SecTaskGetBooleanValueForEntitlement"}, KeyReg: 1, ValueReg: -1},
	objcValueForEntitlementTarget(),
	{Source: SourceDSC, Canonical: "-[NSXPCConnection valueForEntitlement:]", Aliases: []string{"objc_msgSend"}, KeyReg: 2, ValueReg: -1, SelectorReg: 1, Selector: "valueForEntitlement:"},
}

func dscTargets() []targetSpec {
	return dscTargetSpecs
}

func matchTarget(source Source, symbolName string) (targetSpec, bool) {
	clean := cleanSymbolName(symbolName)
	if source == SourceDSC {
		if dyn, ok := matchDynamicDSCTarget(clean); ok {
			return dyn, true
		}
		return matchTargetAliases(clean, dscTargets())
	}
	if target, ok := matchTargetAliases(clean, kernelTargets()); ok {
		return target, true
	}
	if !shouldDemangleTargetSymbol(clean) {
		return targetSpec{}, false
	}
	return matchTargetAliases(symbols.DemangleBareSymbol(clean), kernelTargets())
}

func matchTargetAliases(candidate string, targets []targetSpec) (targetSpec, bool) {
	for _, target := range targets {
		for _, alias := range target.Aliases {
			if targetAliasMatches(candidate, target.Canonical, alias) {
				return target, true
			}
		}
	}
	return targetSpec{}, false
}

func targetAliasMatches(candidate, canonical, alias string) bool {
	if candidate == alias {
		return true
	}
	if strings.Contains(canonical, "::") && !strings.Contains(alias, "::") {
		return false
	}
	return strings.Contains(candidate, alias+"(")
}

func matchDynamicDSCTarget(clean string) (targetSpec, bool) {
	if strings.HasPrefix(clean, "os_entitlement_") {
		return targetSpec{Source: SourceDSC, Canonical: clean, KeyReg: 0, ValueReg: -1}, true
	}
	if strings.HasPrefix(clean, "os_variant") && strings.Contains(clean, "entitlement") {
		return targetSpec{Source: SourceDSC, Canonical: clean, KeyReg: 1, ValueReg: -1}, true
	}
	return targetSpec{}, false
}

func cleanSymbolName(name string) string {
	clean := strings.TrimSpace(name)
	clean = strings.TrimPrefix(clean, "j_")
	clean = strings.TrimPrefix(clean, "__")
	clean = strings.TrimPrefix(clean, "_")
	if idx := strings.Index(clean, " ; "); idx >= 0 {
		clean = clean[:idx]
	}
	return clean
}

func shouldDemangleTargetSymbol(clean string) bool {
	return strings.HasPrefix(clean, "Z") || strings.Contains(clean, "_Z")
}
