package ipsw

import (
	"github.com/blacktop/ipsw/internal/config"
	"github.com/blacktop/ipsw/internal/context"
	"golang.org/x/sync/errgroup"
)

// Pipe for blobs.
type Pipe struct{}

// String returns the description of the pipe.
func (Pipe) String() string                 { return "download ipsw" }
func (Pipe) Skip(ctx *context.Context) bool { return len(ctx.Config.OTAs) == 0 }

// Download downloads the specified IPSW.
func (Pipe) Download(ctx *context.Context) error {
	var g errgroup.Group
	for _, conf := range ctx.Config.OTAs {
		conf := conf
		g.Go(func() error {
			return doDownload(ctx, conf)
		})
	}
	return g.Wait()
}

func doDownload(ctx *context.Context, conf config.OTA) error {
	panic("not implemented")
	return nil
}
