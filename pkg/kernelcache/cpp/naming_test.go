package cpp

import "testing"

// Synthetic addresses for a 3-class hierarchy. No real firmware data.
const (
	gpMeta = 0x1000
	pMeta  = 0x2000
	cMeta  = 0x3000

	gpDtor = 0xfffffe0000010000
	pDtor  = 0xfffffe0000010008
	cDtor  = 0xfffffe0000010010

	gpWork = 0xfffffe0000010100
	cWork  = 0xfffffe0000010108

	gpFn2 = 0xfffffe0000010200
	cFn2  = 0xfffffe0000010208

	gpFn3 = 0xfffffe0000010300
)

// newNamingHierarchy builds a GrandParent -> Parent -> Child hierarchy with four
// index-aligned vtable slots that exercise every naming path:
//
//	slot 0: destructor  -> structor re-synthesis down the chain
//	slot 1: work()      -> authoritative method + override classification
//	slot 2: back-prop   -> Child demangles a name ancestors only guessed
//	slot 3: fn_0x       -> nobody has a symbol; fallback name persists
func newNamingHierarchy() ([]Class, []MethodTable) {
	classes := []Class{
		{Name: "GrandParent", MetaPtr: gpMeta},
		{Name: "Parent", MetaPtr: pMeta, SuperMeta: gpMeta},
		{Name: "Child", MetaPtr: cMeta, SuperMeta: pMeta},
	}
	tables := []MethodTable{
		{Class: "GrandParent", Methods: []VtableEntry{
			{Index: 0, Address: gpDtor, Mangled: "__ZN11GrandParentD2Ev"},
			{Index: 1, Address: gpWork, Mangled: "__ZN11GrandParent4workEv"},
			{Index: 2, Address: gpFn2},
			{Index: 3, Address: gpFn3},
		}},
		{Class: "Parent", Methods: []VtableEntry{
			{Index: 0, Address: pDtor},
			{Index: 1, Address: gpWork},
			{Index: 2, Address: gpFn2},
			{Index: 3, Address: gpFn3},
		}},
		{Class: "Child", Methods: []VtableEntry{
			{Index: 0, Address: cDtor},
			{Index: 1, Address: cWork},
			{Index: 2, Address: cFn2, Mangled: "__ZN5Child5doIt2Ev"},
			{Index: 3, Address: gpFn3},
		}},
	}
	return classes, tables
}

func TestNameMethodTablesStructorSynthesis(t *testing.T) {
	t.Parallel()

	classes, tables := newNamingHierarchy()
	nameMethodTables(classes, tables)

	cases := []struct {
		table  int
		method string
		class  string
	}{
		{0, "~GrandParent()", "GrandParent"},
		{1, "~Parent()", "Parent"},
		{2, "~Child()", "Child"},
	}
	for _, tc := range cases {
		e := tables[tc.table].Methods[0]
		if e.Method != tc.method || e.Class != tc.class {
			t.Fatalf("%s slot0 = %q/%q, want %q/%q", classes[tc.table].Name, e.Class, e.Method, tc.class, tc.method)
		}
		if !e.Structor {
			t.Fatalf("%s slot0 must be flagged structor", classes[tc.table].Name)
		}
	}
	if !tables[0].Methods[0].Authoritative {
		t.Fatal("GrandParent destructor came from a real demangle; want Authoritative")
	}
	if tables[1].Methods[0].ParentAddress != gpDtor {
		t.Fatalf("Parent slot0 ParentAddress = %#x, want %#x", tables[1].Methods[0].ParentAddress, uint64(gpDtor))
	}
}

func TestNameMethodTablesOverrideAndInheritance(t *testing.T) {
	t.Parallel()

	classes, tables := newNamingHierarchy()
	nameMethodTables(classes, tables)

	// Parent inherits work() unchanged: same target -> no override, class stays
	// with the declaring GrandParent, authoritative propagates.
	parent := tables[1].Methods[1]
	if parent.Method != "work()" || parent.Class != "GrandParent" || parent.Overrides || !parent.Authoritative {
		t.Fatalf("Parent slot1 = %+v, want work()/GrandParent, no override, authoritative", parent)
	}

	// Child overrides work() with a different target: override flips, class
	// becomes Child, inherited method name is retained.
	child := tables[2].Methods[1]
	if child.Method != "work()" || child.Class != "Child" || !child.Overrides || !child.Authoritative {
		t.Fatalf("Child slot1 = %+v, want work()/Child, override, authoritative", child)
	}
	if child.ParentAddress != gpWork {
		t.Fatalf("Child slot1 ParentAddress = %#x, want %#x", child.ParentAddress, uint64(gpWork))
	}
}

func TestNameMethodTablesBackPropagation(t *testing.T) {
	t.Parallel()

	classes, tables := newNamingHierarchy()
	nameMethodTables(classes, tables)

	// Child resolves an authoritative name for slot 2 that GrandParent and Parent
	// only guessed; it must back-propagate up the guessed chain.
	child := tables[2].Methods[2]
	if child.Method != "doIt2()" || child.Class != "Child" || !child.Overrides || !child.Authoritative {
		t.Fatalf("Child slot2 = %+v, want doIt2()/Child, override, authoritative", child)
	}
	for _, tbl := range []int{0, 1} {
		e := tables[tbl].Methods[2]
		if e.Method != "doIt2()" {
			t.Fatalf("%s slot2 method = %q, want back-propagated doIt2()", classes[tbl].Name, e.Method)
		}
		if !e.Authoritative {
			t.Fatalf("%s slot2 must become authoritative after back-propagation", classes[tbl].Name)
		}
	}
}

func TestNameMethodTablesFnFallback(t *testing.T) {
	t.Parallel()

	classes, tables := newNamingHierarchy()
	nameMethodTables(classes, tables)

	// Slot 3 has no symbol anywhere and no override; the fn_0x<off> fallback (off
	// = index*8 = 0x18) must persist through inheritance and stay non-authoritative.
	for _, tbl := range []int{0, 1, 2} {
		e := tables[tbl].Methods[3]
		if e.Method != "fn_0x18()" {
			t.Fatalf("%s slot3 method = %q, want fn_0x18()", classes[tbl].Name, e.Method)
		}
		if e.Authoritative {
			t.Fatalf("%s slot3 must stay non-authoritative", classes[tbl].Name)
		}
		if e.Class != classes[tbl].Name {
			// GrandParent declares it; descendants inherit the declaring class.
			if tbl != 0 && e.Class == "GrandParent" {
				continue
			}
			t.Fatalf("%s slot3 class = %q", classes[tbl].Name, e.Class)
		}
	}
}

func TestClassBasename(t *testing.T) {
	t.Parallel()

	cases := map[string]string{
		"Child":                  "Child",
		"Foo::Bar":               "Bar",
		"Foo::Bar<Baz>":          "Bar",
		"OSCollection":           "OSCollection",
		"ns::Outer<A::B>::Inner": "Inner",
	}
	for in, want := range cases {
		if got := classBasename(in); got != want {
			t.Fatalf("classBasename(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestSplitClassMethod(t *testing.T) {
	t.Parallel()

	cases := []struct {
		in     string
		class  string
		method string
		ok     bool
	}{
		{"GrandParent::~GrandParent()", "GrandParent", "~GrandParent()", true},
		{"Foo::bar(int)", "Foo", "bar(int)", true},
		{"Foo<A::B>::baz()", "Foo<A::B>", "baz()", true},
		{"noColons", "", "", false},
	}
	for _, tc := range cases {
		class, method, ok := splitClassMethod(tc.in)
		if ok != tc.ok || class != tc.class || method != tc.method {
			t.Fatalf("splitClassMethod(%q) = %q/%q/%v, want %q/%q/%v", tc.in, class, method, ok, tc.class, tc.method, tc.ok)
		}
	}
}
