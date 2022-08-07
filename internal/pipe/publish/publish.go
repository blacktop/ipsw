// Package publish contains the publishing pipe.
package publish

import (
	"context"
	"fmt"

	"github.com/blacktop/ipsw/internal/pipe/s3"
)

// Publisher should be implemented by pipes that want to publish artifacts.
type Publisher interface {
	fmt.Stringer

	// Default sets the configuration defaults
	Publish(ctx *context.Context) error
}

// nolint: gochecknoglobals
var publishers = []Publisher{
	s3.Pipe{},
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
