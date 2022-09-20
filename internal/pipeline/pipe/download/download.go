// Package download contains the downloading pipe.
package download

import (
	"fmt"

	"github.com/blacktop/ipsw/internal/pipeline/context"
	"github.com/blacktop/ipsw/internal/pipeline/middleware/errhandler"
	"github.com/blacktop/ipsw/internal/pipeline/middleware/logging"
	"github.com/blacktop/ipsw/internal/pipeline/middleware/skip"
	"github.com/blacktop/ipsw/internal/pipeline/pipe/ipsw"
	"github.com/blacktop/ipsw/internal/pipeline/pipe/ota"
)

// Downloader should be implemented by pipes that want to download files.
type Downloader interface {
	fmt.Stringer

	// Download downloads the file.
	Download(ctx *context.Context) error
}

// nolint: gochecknoglobals
var downloaders = []Downloader{
	ipsw.Pipe{},
	ota.Pipe{},
}

// Pipe that publishes artifacts.
type Pipe struct{}

func (Pipe) String() string                 { return "downloading" }
func (Pipe) Skip(ctx *context.Context) bool { return ctx.SkipDownload }

func (Pipe) Run(ctx *context.Context) error {
	for _, downloader := range downloaders {
		if err := skip.Maybe(
			downloader,
			logging.PadLog(
				downloader.String(),
				errhandler.Handle(downloader.Download),
			),
		)(ctx); err != nil {
			return fmt.Errorf("%s: failed to download files: %w", downloader.String(), err)
		}
	}
	return nil
}
