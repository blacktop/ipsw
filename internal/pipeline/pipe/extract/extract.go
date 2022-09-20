package extract

import (
	"github.com/blacktop/ipsw/internal/pipeline/config"
	"github.com/blacktop/ipsw/internal/pipeline/context"
	"golang.org/x/sync/errgroup"
)

// Pipe for extract.
type Pipe struct{}

// String returns the description of the pipe.
func (Pipe) String() string                 { return "extract" }
func (Pipe) Skip(ctx *context.Context) bool { return len(ctx.Config.Extracts) == 0 }

// Run extracts the file.
func (Pipe) Run(ctx *context.Context) error {
	var g errgroup.Group
	for _, conf := range ctx.Config.Extracts {
		conf := conf
		g.Go(func() error {
			return doExtract(ctx, conf)
		})
	}
	return g.Wait()
}

func doExtract(ctx *context.Context, conf config.Extract) error {
	panic("not implemented")
	return nil
}
