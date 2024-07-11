// Code generated from Pkl module `io.blacktop.Symbolicator`. DO NOT EDIT.
package signature

import (
	"context"

	"github.com/apple/pkl-go/pkl"
)

type Symbolicator struct {
	Signatures []*Signature `pkl:"signatures"`
}

// LoadFromPath loads the pkl module at the given path and evaluates it into a Symbolicator
func LoadFromPath(ctx context.Context, path string) (ret *Symbolicator, err error) {
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

// Load loads the pkl module at the given source and evaluates it with the given evaluator into a Symbolicator
func Load(ctx context.Context, evaluator pkl.Evaluator, source *pkl.ModuleSource) (*Symbolicator, error) {
	var ret Symbolicator
	if err := evaluator.EvaluateModule(ctx, source, &ret); err != nil {
		return nil, err
	}
	return &ret, nil
}
