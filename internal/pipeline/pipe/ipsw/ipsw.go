package ipsw

import (
	"github.com/blacktop/ipsw/internal/pipeline/config"
	"github.com/blacktop/ipsw/internal/pipeline/context"
	"golang.org/x/sync/errgroup"
)

// Pipe for ipsws.
type Pipe struct{}

// String returns the description of the pipe.
func (Pipe) String() string                 { return "download ipsw" }
func (Pipe) Skip(ctx *context.Context) bool { return len(ctx.Config.Downloads.IPSWs) == 0 }

// Download downloads the specified OTA.
func (Pipe) Download(ctx *context.Context) error {
	var g errgroup.Group
	for _, conf := range ctx.Config.Downloads.IPSWs {
		conf := conf
		g.Go(func() error {
			return doDownload(ctx, conf)
		})
	}
	return g.Wait()
}

func doDownload(ctx *context.Context, conf config.IPSW) error {
	panic("not implemented")
	return nil
}
