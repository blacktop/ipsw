// Package publish contains the publishing pipe.
package publish

import (
	"fmt"

	"github.com/blacktop/ipsw/internal/pipeline/context"
	"github.com/blacktop/ipsw/internal/pipeline/middleware/errhandler"
	"github.com/blacktop/ipsw/internal/pipeline/middleware/logging"
	"github.com/blacktop/ipsw/internal/pipeline/middleware/skip"
	"github.com/blacktop/ipsw/internal/pipeline/pipe/blob"
)

// Publisher should be implemented by pipes that want to publish artifacts.
type Publisher interface {
	fmt.Stringer

	// Default sets the configuration defaults
	Publish(ctx *context.Context) error
}

// nolint: gochecknoglobals
var publishers = []Publisher{
	blob.Pipe{},
}

// Pipe that publishes artifacts.
type Pipe struct{}

func (Pipe) String() string                 { return "publishing" }
func (Pipe) Skip(ctx *context.Context) bool { return ctx.SkipPublish }

func (Pipe) Run(ctx *context.Context) error {
	for _, publisher := range publishers {
		if err := skip.Maybe(
			publisher,
			logging.PadLog(
				publisher.String(),
				errhandler.Handle(publisher.Publish),
			),
		)(ctx); err != nil {
			return fmt.Errorf("%s: failed to publish artifacts: %w", publisher.String(), err)
		}
	}
	return nil
}
