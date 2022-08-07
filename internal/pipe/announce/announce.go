// Package announce contains the announcing pipe.
package announce

import (
	"context"
	"fmt"

	"github.com/apex/log"
	"github.com/blacktop/ipsw/internal/pipe/mattermost"
)

// Announcer should be implemented by pipes that want to announce releases.
type Announcer interface {
	fmt.Stringer
	Announce(ctx *context.Context) error
}

var announcers = []Announcer{
	mattermost.Pipe{},
}

// Pipe that announces releases.
type Pipe struct{}

func (Pipe) String() string { return "announcing" }

func (Pipe) Skip(ctx *context.Context) bool {
	if ctx.SkipAnnounce {
		return true
	}
	if ctx.Config.Announce.Skip == "" {
		return false
	}
	skip, err := tmpl.New(ctx).Apply(ctx.Config.Announce.Skip)
	if err != nil {
		log.Error("invalid announce.skip template, will skip the announcing step")
		return true
	}
	log.Debugf("announce.skip evaluated from %q to %q", ctx.Config.Announce.Skip, skip)
	return skip == "true"
}

// Run the pipe.
func (Pipe) Run(ctx *context.Context) error {
	for _, announcer := range announcers {
		if err := skip.Maybe(
			announcer,
			logging.PadLog(
				announcer.String(),
				errhandler.Handle(announcer.Announce),
			),
		)(ctx); err != nil {
			return fmt.Errorf("%s: failed to announce release: %w", announcer.String(), err)
		}
	}
	return nil
}
