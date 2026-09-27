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
	relocated := map[string]*objc.Class{"A": {Name: "A", InstanceMethods: []objc.Method{{Name: "m", ImpVMAddr: 0x1000}}}}
	if out := diffClasses(same, relocated); !strings.Contains(out, "@@ Classes: no changes @@") {
		t.Errorf("implementation addresses must not affect structural diff:\n%s", out)
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

func TestObjCDiffProperties(t *testing.T) {
	for _, surface := range []struct {
		name string
		diff func([]objc.Property, []objc.Property) string
	}{
		{"class", func(prev, next []objc.Property) string {
			return diffClasses(map[string]*objc.Class{"A": {Name: "A", InstanceMethods: meths("value"), Props: prev}},
				map[string]*objc.Class{"A": {Name: "A", InstanceMethods: meths("value"), Props: next}})
		}},
		{"category", func(prev, next []objc.Property) string {
			return diffCategories(map[string]*objc.Category{"A": {Name: "A", InstanceMethods: meths("value"), Properties: prev}},
				map[string]*objc.Category{"A": {Name: "A", InstanceMethods: meths("value"), Properties: next}})
		}},
		{"protocol", func(prev, next []objc.Property) string {
			return diffProtocols(map[string]*objc.Protocol{"A": {Name: "A", InstanceMethods: meths("value"), InstanceProperties: prev}},
				map[string]*objc.Protocol{"A": {Name: "A", InstanceMethods: meths("value"), InstanceProperties: next}})
		}},
		{"class protocol", func(prev, next []objc.Property) string {
			return diffProtocols(map[string]*objc.Protocol{"A": {Name: "A", ClassMethods: meths("value"), ClassProperties: prev}},
				map[string]*objc.Protocol{"A": {Name: "A", ClassMethods: meths("value"), ClassProperties: next}})
		}},
	} {
		t.Run(surface.name, func(t *testing.T) {
			for _, tt := range []struct{ name, prev, next string }{
				{"type", "Ti,V_value", "Tq,V_value"},
				{"readonly", "Ti,V_value", "Ti,R,V_value"},
				{"backing ivar", "Ti,V_value", "Ti,V_other"},
				{"ownership", "T@,&,V_value", "T@,C,V_value"},
				{"getter", "Ti,Gvalue,V_value", "Ti,GcustomValue,V_value"},
				{"setter", "Ti,SsetValue:,V_value", "Ti,SstoreValue:,V_value"},
				{"quoted type", "T{Pair=\"left,right\"ii},V_value", "T{Pair=\"right,left\"ii},V_value"},
			} {
				t.Run(tt.name, func(t *testing.T) {
					prev := []objc.Property{{Name: "value", EncodedAttributes: tt.prev}}
					next := []objc.Property{{Name: "value", EncodedAttributes: tt.next}}
					out := surface.diff(prev, next)
					if !strings.Contains(out, "~1 changed") || !strings.Contains(out, "+   @property") || !strings.Contains(out, "-   @property") {
						t.Fatalf("property-only change missing: %s", out)
					}
				})
			}
			props := []objc.Property{{Name: "value", EncodedAttributes: "Ti,R,V_value"}}
			for _, change := range []struct {
				prev, next []objc.Property
				marker     string
			}{{nil, props, "+   @property"}, {props, nil, "-   @property"}} {
				if out := surface.diff(change.prev, change.next); !strings.Contains(out, change.marker) || !strings.Contains(out, "~1 changed") {
					t.Fatalf("property addition/removal missing: %s", out)
				}
			}
			prev := []objc.Property{{Name: "value", EncodedAttributes: "T{Pair=\"left,right\"ii},R,N,V_value"}}
			next := []objc.Property{{Name: "value", EncodedAttributes: "V_value,N,T{Pair=\"left,right\"ii},R", PropertyT: objc.PropertyT{NameVMAddr: 0x1000}}}
			if out := surface.diff(prev, next); !strings.Contains(out, "no changes") {
				t.Fatalf("attribute reordering or address changed diff: %s", out)
			}
		})
	}
}
