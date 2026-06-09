package macho

import (
	"strings"
	"testing"

	"github.com/blacktop/go-macho/types/objc"
)

func meths(names ...string) []objc.Method {
	m := make([]objc.Method, len(names))
	for i, n := range names {
		m[i] = objc.Method{Name: n}
	}
	return m
}

func TestDiffClassesAddedRemovedChanged(t *testing.T) {
	prev := map[string]*objc.Class{
		"Gone":    {Name: "Gone"},
		"Stable":  {Name: "Stable", InstanceMethods: meths("a", "b")},
		"Changed": {Name: "Changed", InstanceMethods: meths("keep", "drop")},
	}
	next := map[string]*objc.Class{
		"New":     {Name: "New", SuperClass: "NSObject", InstanceMethods: meths("x")},
		"Stable":  {Name: "Stable", InstanceMethods: meths("a", "b")},
		"Changed": {Name: "Changed", InstanceMethods: meths("keep", "add"), ClassMethods: meths("alloc")},
	}

	out := diffClasses(prev, next)

	if !strings.Contains(out, "@@ Classes: +1 added, -1 removed, ~1 changed @@") {
		t.Errorf("summary wrong:\n%s", out)
	}
	if !strings.Contains(out, "\n+ New : NSObject  (1 methods)\n") {
		t.Errorf("added class missing (col-0 '+'):\n%s", out)
	}
	if !strings.Contains(out, "\n- Gone\n") {
		t.Errorf("removed class missing (col-0 '-'):\n%s", out)
	}
	// Changed class: context line, then +instance add, +class alloc, -instance drop.
	for _, want := range []string{"\n Changed\n", "+   -add", "+   +alloc", "-   -drop"} {
		if !strings.Contains(out, want) {
			t.Errorf("changed-class delta missing %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "Stable") {
		t.Errorf("unchanged class should not appear:\n%s", out)
	}
}

func TestDiffProtocolsIncludesOptionalMethods(t *testing.T) {
	prev := map[string]*objc.Protocol{
		"P": {Name: "P", InstanceMethods: meths("req")},
	}
	next := map[string]*objc.Protocol{
		"P": {Name: "P", InstanceMethods: meths("req"), OptionalInstanceMethods: meths("opt")},
	}
	out := diffProtocols(prev, next)
	if !strings.Contains(out, "@@ Protocols: +0 added, -0 removed, ~1 changed @@") {
		t.Errorf("expected 1 changed protocol:\n%s", out)
	}
	if !strings.Contains(out, "+   -opt") {
		t.Errorf("added optional instance method should appear as '+   -opt':\n%s", out)
	}
}

func TestDiffClassesNoChange(t *testing.T) {
	same := map[string]*objc.Class{"A": {Name: "A", InstanceMethods: meths("m")}}
	if out := diffClasses(same, same); !strings.Contains(out, "@@ Classes: no changes @@") {
		t.Errorf("expected 'no changes', got:\n%s", out)
	}
}

func TestAddedRemovedSortedAndDisjoint(t *testing.T) {
	prev := map[string]struct{}{"-old": {}, "-shared": {}}
	next := map[string]struct{}{"-shared": {}, "-new": {}, "+cls": {}}
	added, removed := addedRemoved(prev, next)
	if strings.Join(added, ",") != "+cls,-new" { // sorted: '+' (0x2b) < '-' (0x2d)
		t.Errorf("added = %v, want [+cls -new]", added)
	}
	if strings.Join(removed, ",") != "-old" {
		t.Errorf("removed = %v, want [-old]", removed)
	}
}

func TestMethodKeysInstanceVsClass(t *testing.T) {
	keys := methodKeys(meths("inst:"), meths("cls"))
	if _, ok := keys["-inst:"]; !ok {
		t.Error("instance method should key as '-inst:'")
	}
	if _, ok := keys["+cls"]; !ok {
		t.Error("class method should key as '+cls'")
	}
}
