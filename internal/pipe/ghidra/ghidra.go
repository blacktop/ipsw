// Package ghidra contains the Ghidra pipe.
package ghidra

import (
	"fmt"
	"os/exec"

	"github.com/apex/log"
	"github.com/blacktop/ipsw/internal/config"
	"github.com/blacktop/ipsw/internal/context"
	"github.com/blacktop/ipsw/internal/pipe"
	"golang.org/x/sync/errgroup"
)

// Pipe that runs dockerized pipelines.
type Pipe struct{}

func (Pipe) String() string                 { return "ghidra" }
func (Pipe) Skip(ctx *context.Context) bool { return len(ctx.Config.Ghidras) == 0 }

// Run the pipe.
func (Pipe) Run(ctx *context.Context) error {
	// g := semerrgroup.NewSkipAware(semerrgroup.New(ctx.Parallelism))
	var g errgroup.Group
	for _, ghi := range ctx.Config.Ghidras {
		ghi := ghi
		g.Go(func() error {
			log.WithField("ghidra", ghi).Debug("running ghidra pipe")
			return runGhidra(ctx, ghi)
		})
	}
	if err := g.Wait(); err != nil {
		if pipe.IsSkip(err) {
			return err
		}
		return fmt.Errorf("ida pro pipe failed: %w", err)
	}
	return nil
}

func runGhidra(ctx *context.Context, conf config.Ghidra) error {
	client, err := NewClient(&conf)
	if err != nil {
		return err
	}
	return client.Run()
}

type Client struct {
	conf *config.Ghidra
	cmd  *exec.Cmd
}

func NewClient(conf *config.Ghidra) (*Client, error) {
	return &Client{conf: conf, cmd: exec.Command(executable, args...)}, nil
}

func (c *Client) Run() error {
	return c.cmd.Run()
}
