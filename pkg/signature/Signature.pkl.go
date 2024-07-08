// Code generated from Pkl module `io.blacktop.Signature`. DO NOT EDIT.
package signature

import (
	"context"

	"github.com/apple/pkl-go/pkl"
)

type Signature struct {
	// The number of args.
	Args uint16 `pkl:"args"`

	// The string in function.
	Pattern string `pkl:"pattern"`

	// The name of the function this signature matches.
	Symbol string `pkl:"symbol"`

	// The name of the function that calls this function.
	Caller string `pkl:"caller"`
}

// LoadFromPath loads the pkl module at the given path and evaluates it into a Signature
func LoadFromPath(ctx context.Context, path string) (ret *Signature, err error) {
	evaluator, err := pkl.NewEvaluator(ctx, pkl.PreconfiguredOptions)
	if err != nil {
		return nil, err
	}
	defer func() {
		cerr := evaluator.Close()
		if err == nil {
			err = cerr
		}
	}()
	ret, err = Load(ctx, evaluator, pkl.FileSource(path))
	return ret, err
}

// Load loads the pkl module at the given source and evaluates it with the given evaluator into a Signature
func Load(ctx context.Context, evaluator pkl.Evaluator, source *pkl.ModuleSource) (*Signature, error) {
	var ret Signature
	if err := evaluator.EvaluateModule(ctx, source, &ret); err != nil {
		return nil, err
	}
	return &ret, nil
}
