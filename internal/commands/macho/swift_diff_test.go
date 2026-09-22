package macho

import (
	"strings"
	"testing"

	stypes "github.com/blacktop/go-macho/types/swift"
)

func swiftEntities(keyed ...string) map[string]*swiftEntity {
	out := map[string]*swiftEntity{}
	for i := 0; i+1 < len(keyed); i += 2 {
		addSwiftEntity(out, keyed[i], keyed[i+1])
	}
	return out
}

func TestNewSwiftEntityMembers(t *testing.T) {
	e := newSwiftEntity("class Fake.Widget", `typealias WidgetRef Widget
class Fake.Widget<A: Swift.Equatable>: NSObject
  where A == Swift.Int {
  /* fields */
    let size: Swift.Int
  /* methods */
    func sub_1a2b3c // method __ptrauth(be2f) (instance)
}`)
	want := []string{
		"typealias WidgetRef Widget",
		"class Fake.Widget<A: Swift.Equatable>: NSObject",
		"where A == Swift.Int",
		"let size: Swift.Int",
		"func sub_ // method __ptrauth(be2f) (instance)",
	}
	for _, w := range want {
		if _, ok := e.members[w]; !ok {
			t.Errorf("missing member %q in %v", w, e.members)
		}
	}
	if len(e.members) != len(want) {
		t.Errorf("section labels and braces should not be members: %v", e.members)
	}
	if e := newSwiftEntity("module Fake", "module Fake"); len(e.members) != 1 {
		t.Errorf("bodiless declaration should keep its header as a member: %v", e.members)
	}
}

func TestSwiftKeysDropGenericSignature(t *testing.T) {
	inner := stypes.Type{Kind: stypes.CDKindClass, Name: "Inner", Parent: &stypes.Type{Name: "Multicast", Parent: &stypes.Type{Name: "Fake"}}}
	if got := swiftTypeKey(inner); got != "class Fake.Multicast.Inner" {
		t.Errorf("type key = %q", got)
	}
	top := stypes.Type{Kind: stypes.CDKindStruct, Name: "Top", Parent: &stypes.Type{Parent: &stypes.Type{}}}
	if got := swiftTypeKey(top); got != "struct Top" {
		t.Errorf("type key with empty parents = %q", got)
	}
	proto := stypes.Protocol{Name: "Publishing", Parent: &stypes.TargetModuleContext{Name: "Fake"}}
	if got := swiftProtocolKey(proto); got != "protocol Fake.Publishing" {
		t.Errorf("protocol key = %q", got)
	}
	conf := stypes.ConformanceDescriptor{Protocol: "Swift.Hashable", TypeRef: &stypes.Type{Name: "Mode", Parent: &stypes.Type{Name: "Fake"}}}
	if got := swiftConformanceKey(conf); got != "protocol conformance Fake.Mode : Swift.Hashable" {
		t.Errorf("conformance key = %q", got)
	}
	if got := swiftConformanceKey(stypes.ConformanceDescriptor{Protocol: "P"}); got != "protocol conformance  : P" {
		t.Errorf("conformance key without type ref = %q", got)
	}
	assoc := stypes.AssociatedType{ConformingTypeName: "Fake.Mode", ProtocolTypeName: "RawRepresentable"}
	if got := swiftAssociatedTypeKey(assoc); got != "extension Fake.Mode: RawRepresentable" {
		t.Errorf("associated type key = %q", got)
	}
}

func TestDiffSwiftEntitiesAddedRemovedChanged(t *testing.T) {
	prev := swiftEntities(
		"struct Fake.Gone", "struct Fake.Gone {\n    let a: Swift.Int\n}",
		"enum Fake.Mode", "enum Fake.Mode {\n    case on\n    case legacy\n}",
	)
	next := swiftEntities(
		"class Fake.New", "class Fake.New {\n    let b: Swift.Bool\n}",
		"enum Fake.Mode", "enum Fake.Mode {\n    case on\n    case off\n}",
	)

	out := diffSwiftEntities("Types", prev, next)

	for _, want := range []string{
		"@@ Types: +1 added, -1 removed, ~1 changed @@",
		"\n+ class Fake.New  (2 members)\n",
		"\n- struct Fake.Gone\n",
		"\n enum Fake.Mode\n",
		"+   case off",
		"-   case legacy",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in:\n%s", want, out)
		}
	}
	if strings.Contains(out, "case on") {
		t.Errorf("unchanged member should not appear:\n%s", out)
	}
}

func TestDiffSwiftEntitiesSuperclassChangeIsAChange(t *testing.T) {
	prev := swiftEntities("class Fake.A", "class Fake.A: NSObject {\n    let x: Swift.Int\n}")
	next := swiftEntities("class Fake.A", "class Fake.A: Fake.Base {\n    let x: Swift.Int\n}")
	out := diffSwiftEntities("Types", prev, next)
	for _, want := range []string{"~1 changed", "\n class Fake.A\n", "+   class Fake.A: Fake.Base", "-   class Fake.A: NSObject"} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in:\n%s", want, out)
		}
	}
}

func TestDiffSwiftModelsIgnoresAddressOnlyChanges(t *testing.T) {
	model := func(addr string) *swiftModel {
		return &swiftModel{
			types:        swiftEntities("class Fake.A", "class Fake.A {\n    func sub_"+addr+" // method __ptrauth(375e) (instance)\n}"),
			protocols:    swiftEntities(),
			conformances: swiftEntities("protocol conformance Fake.A : Swift.Hashable", "protocol conformance Fake.A : Swift.Hashable {\n    func sub_"+addr+" // getter __ptrauth(026b)\n}"),
			assocTypes:   swiftEntities(),
		}
	}
	out := diffSwiftModels("Fake", model("100004000"), model("100008abc"))
	for _, title := range []string{"Types", "Protocols", "Conformances", "Associated Types"} {
		if !strings.Contains(out, "@@ "+title+": no changes @@") {
			t.Errorf("rebuild with moved functions should report no %s changes:\n%s", title, out)
		}
	}
	if !strings.HasPrefix(out, "# Swift diff: Fake\n\n```diff\n") {
		t.Errorf("unexpected header:\n%s", out)
	}
}

func TestDiffSwiftEntitiesPtrauthSurvivesNormalization(t *testing.T) {
	prev := swiftEntities("class Fake.A", "class Fake.A {\n    func sub_100004000 // method __ptrauth(1111) (instance)\n}")
	next := swiftEntities("class Fake.A", "class Fake.A {\n    func sub_100008abc // method __ptrauth(2222) (instance)\n}")
	out := diffSwiftEntities("Types", prev, next)
	if !strings.Contains(out, "+   func sub_ // method __ptrauth(2222) (instance)") ||
		!strings.Contains(out, "-   func sub_ // method __ptrauth(1111) (instance)") {
		t.Errorf("a changed discriminator identifies a changed method after address normalization:\n%s", out)
	}
}

func TestAddSwiftEntityMergesDuplicateKeys(t *testing.T) {
	got := swiftEntities(
		"opaque_type", "opaque_type {\n    Swift.Int\n}",
		"opaque_type", "opaque_type {\n    Swift.String\n}",
	)
	if len(got) != 1 || len(got["opaque_type"].members) != 3 {
		t.Errorf("duplicate keys should merge members, got %v", got)
	}
}
