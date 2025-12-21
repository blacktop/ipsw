package symbols

import "testing"

func TestDemangleSymbolName(t *testing.T) {
	tcs := map[string]string{
		"_ZN3Foo3barEv":                  "Foo::bar()",
		"__ZdlPv":                        "operator delete(void*)",
		"__stub_helper._ZN3Foo3barEv":    "__stub_helper.Foo::bar()",
		"__stub_helper.__ZN3Foo3barEv":   "__stub_helper.Foo::bar()",
		"j___stub_helper._ZN3Foo3barEv":  "j___stub_helper.Foo::bar()",
		"__got._ZN3Foo3barEv":            "__got.Foo::bar()",
		"__stub_helper._ZN3Foo3barEv+4":  "__stub_helper.Foo::bar()+4",
		"__stub_helper._ZN3Foo3barEv+ 4": "__stub_helper.Foo::bar()+ 4",
	}

	for in, want := range tcs {
		if got := DemangleSymbolName(in); got != want {
			t.Errorf("DemangleSymbolName(%q) = %q, want %q", in, got, want)
		}
	}
}
