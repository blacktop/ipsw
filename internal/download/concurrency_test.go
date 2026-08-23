package download

import (
	"strings"
	"testing"
)

func TestPolicyOverrideValidationBoundaries(t *testing.T) {
	preservePolicyOverrides(t)
	for _, test := range []struct {
		name string
		in   PolicyOverrides
		want string
	}{
		{name: "profile defaults"},
		{name: "single stream", in: PolicyOverrides{Parts: 1}},
		{name: "maximum parts", in: PolicyOverrides{Parts: MaxParts, MinParts: MaxParts}},
		{name: "negative parts", in: PolicyOverrides{Parts: -1}, want: "parts must be 0"},
		{name: "parts above cap", in: PolicyOverrides{Parts: MaxParts + 1}, want: "parts must be 0"},
		{name: "negative min-parts", in: PolicyOverrides{MinParts: -1}, want: "min-parts must be 0"},
		{
			name: "min-parts above cap", in: PolicyOverrides{MinParts: MaxParts + 1},
			want: "min-parts must be 0",
		},
		{
			name: "floor above parts", in: PolicyOverrides{Parts: 4, MinParts: 5},
			want: "min-parts must satisfy",
		},
		{
			name: "negative min-part-size", in: PolicyOverrides{MinPartSize: -1},
			want: "min-part-size must be >= 0",
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			err := SetPolicyOverrides(test.in)
			if test.want == "" {
				if err != nil {
					t.Fatalf("SetPolicyOverrides(%+v) = %v", test.in, err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("SetPolicyOverrides(%+v) = %v, want error containing %q",
					test.in, err, test.want)
			}
		})
	}
}

func TestInvalidPolicyOverrideLeavesPriorState(t *testing.T) {
	preservePolicyOverrides(t)
	want := PolicyOverrides{
		Parts: 5, MinParts: 2, MinPartSize: 7 << 20, EnableNodeSelection: true,
	}
	if err := SetPolicyOverrides(want); err != nil {
		t.Fatal(err)
	}
	if err := SetPolicyOverrides(PolicyOverrides{Parts: 2, MinParts: 3}); err == nil {
		t.Fatal("SetPolicyOverrides accepted an inconsistent policy")
	}
	if got := GetPolicyOverrides(); got != want {
		t.Fatalf("invalid override changed state to %+v, want %+v", got, want)
	}
}
