package errhandler

import (
	"github.com/apex/log"
	"github.com/blacktop/ipsw/internal/pipeline/context"
	"github.com/blacktop/ipsw/internal/pipeline/middleware"
	"github.com/blacktop/ipsw/internal/pipeline/pipe"
)

// Handle handles an action error, ignoring and logging pipe skipped
// errors.
func Handle(action middleware.Action) middleware.Action {
	return func(ctx *context.Context) error {
		err := action(ctx)
		if err == nil {
			return nil
		}
		if pipe.IsSkip(err) {
			log.WithField("reason", err.Error()).Warn("pipe skipped")
			return nil
		}
		return err
	}
}
