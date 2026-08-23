package download

import (
	"strings"
	"testing"
)

func TestConcurrencyReachesEngineOptions(t *testing.T) {
	prev := GetConcurrency()
	t.Cleanup(func() {
		if err := SetConcurrency(prev); err != nil {
			t.Fatal(err)
		}
	})

	d := NewDownload("", false, false, false, false)
	opts := d.options()
	if opts.Parts != DefaultParts || opts.MinParts != DefaultMinParts {
		t.Fatalf("default options = parts %d / min-parts %d, want %d / %d",
			opts.Parts, opts.MinParts, DefaultParts, DefaultMinParts)
	}

	if err := SetConcurrency(Concurrency{Parts: 4, MinParts: 4}); err != nil {
		t.Fatal(err)
	}
	opts = d.options()
	if opts.Parts != 4 || opts.MinParts != 4 {
		t.Fatalf("options after SetConcurrency = parts %d / min-parts %d, want 4 / 4",
			opts.Parts, opts.MinParts)
	}
}

func TestConcurrencyValidation(t *testing.T) {
	for _, tc := range []struct {
		name string
		c    Concurrency
		want string // substring of the error; "" means valid
	}{
		{name: "defaults", c: Concurrency{Parts: DefaultParts, MinParts: DefaultMinParts}},
		{name: "fixed parallelism", c: Concurrency{Parts: 8, MinParts: 8}},
		{name: "single flow", c: Concurrency{Parts: 1, MinParts: 1}},
		{name: "zero parts", c: Concurrency{Parts: 0, MinParts: 1}, want: "parts must satisfy"},
		{name: "parts above cap", c: Concurrency{Parts: MaxParts + 1, MinParts: 1}, want: "parts must satisfy"},
		{name: "parts at cap", c: Concurrency{Parts: MaxParts, MinParts: 1}},
		{name: "zero min-parts", c: Concurrency{Parts: 8, MinParts: 0}, want: "min-parts must satisfy"},
		{name: "floor above cap", c: Concurrency{Parts: 4, MinParts: 5}, want: "min-parts must satisfy"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.c.Validate()
			if tc.want == "" {
				if err != nil {
					t.Fatalf("Validate(%+v) = %v, want nil", tc.c, err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("Validate(%+v) = %v, want error containing %q", tc.c, err, tc.want)
			}
		})
	}
	prev := GetConcurrency()
	if err := SetConcurrency(Concurrency{Parts: 4, MinParts: 9}); err == nil {
		t.Fatal("SetConcurrency accepted an invalid policy")
	}
	if got := GetConcurrency(); got != prev {
		t.Fatalf("invalid SetConcurrency changed the policy to %+v", got)
	}
}
