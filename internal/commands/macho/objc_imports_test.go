package macho

import (
	"slices"
	"testing"

	"github.com/blacktop/go-macho/types/objc"
)

// TestFillImportsForMethod_WellFormed verifies the helper collects imports for
// the return type and every real argument (including the last one, which a prior
// off-by-one dropped), and never for the implicit self/_cmd parameters.
func TestFillImportsForMethod_WellFormed(t *testing.T) {
	o := &ObjC{}
	var imp Imports
	// - (void)doThing:(NSArray *)a with:(NSData *)b
	method := objc.Method{Types: "v32@0:8@\"NSArray\"16@\"NSData\"24"}
	if err := o.fillImportsForMethod(method, "Owner", "", nil, nil, &imp); err != nil {
		t.Fatalf("fillImportsForMethod: %v", err)
	}
	for _, want := range []string{"NSArray", "NSData"} {
		if !contains(imp.Classes, want) {
			t.Errorf("missing import %q; got Classes=%v", want, imp.Classes)
		}
	}
	if contains(imp.Classes, "id") || contains(imp.Classes, "SEL") {
		t.Errorf("self/_cmd leaked into imports: Classes=%v", imp.Classes)
	}
}

// TestFillImportsForMethod_Malformed verifies a truncated/garbage type encoding
// does not inject a bogus import (e.g. a stray "=" fragment or the "<error>"
// out-of-range sentinel becoming "@class =;" / "@protocol error;").
func TestFillImportsForMethod_Malformed(t *testing.T) {
	o := &ObjC{}
	for _, types := range []string{"v16@0:8{Foo=", "v16@0:8^^", "i16@0:8{X="} {
		var imp Imports
		method := objc.Method{Types: types}
		if err := o.fillImportsForMethod(method, "Owner", "", nil, nil, &imp); err != nil {
			t.Fatalf("fillImportsForMethod(%q): %v", types, err)
		}
		for _, junk := range []string{"=", "<error>", "error", "{Foo", "{X"} {
			if contains(imp.Classes, junk) || contains(imp.Protos, junk) {
				t.Errorf("types %q injected bogus import %q (Classes=%v Protos=%v)", types, junk, imp.Classes, imp.Protos)
			}
		}
	}
}

func contains(s []string, v string) bool {
	return slices.Contains(s, v)
}
