package pacx

import (
	"errors"
	"testing"

	mtypes "github.com/blacktop/go-macho/types"
)

func TestFunctionsForScanFallsBackToGeneratedStarts(t *testing.T) {
	t.Parallel()

	called := false
	funcs, err := functionsForScan(nil, func() ([]mtypes.Function, error) {
		called = true
		return []mtypes.Function{
			{StartAddr: 0xfffffe0007101000, EndAddr: 0xfffffe0007101100},
			{StartAddr: 0xfffffe0007100000, EndAddr: 0xfffffe0007100100},
		}, nil
	})
	if err != nil {
		t.Fatalf("functionsForScan: %v", err)
	}
	if !called {
		t.Fatal("GenerateFunctionStarts fallback was not called")
	}
	if len(funcs) != 2 || funcs[0].StartAddr != 0xfffffe0007100000 || funcs[1].StartAddr != 0xfffffe0007101000 {
		t.Fatalf("functions not generated and sorted: %+v", funcs)
	}
}

func TestFunctionsForScanKeepsDirectStarts(t *testing.T) {
	t.Parallel()

	direct := []mtypes.Function{{StartAddr: 0xfffffe0007100000, EndAddr: 0xfffffe0007100100}}
	funcs, err := functionsForScan(direct, func() ([]mtypes.Function, error) {
		t.Fatal("GenerateFunctionStarts should not be called when direct starts exist")
		return nil, nil
	})
	if err != nil {
		t.Fatalf("functionsForScan: %v", err)
	}
	if len(funcs) != 1 || funcs[0].StartAddr != direct[0].StartAddr {
		t.Fatalf("direct functions changed: %+v", funcs)
	}
}

func TestFunctionsForScanReturnsGeneratedError(t *testing.T) {
	t.Parallel()

	want := errors.New("no prologues")
	if _, err := functionsForScan(nil, func() ([]mtypes.Function, error) { return nil, want }); err == nil {
		t.Fatal("functionsForScan returned nil error")
	} else if !errors.Is(err, want) {
		t.Fatalf("functionsForScan error = %v, want wrapping %v", err, want)
	}
}
