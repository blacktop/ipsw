// Package ghidra contains the Ghidra pipe.
package ghidra

import (
	"fmt"
	"os/exec"

	"github.com/apex/log"
	"github.com/blacktop/ipsw/internal/pipeline/config"
	"github.com/blacktop/ipsw/internal/pipeline/context"
	"github.com/blacktop/ipsw/internal/pipeline/pipe"
	"golang.org/x/sync/errgroup"
)

// Pipe that runs dockerized pipelines.
type Pipe struct{}

func (Pipe) String() string                 { return "ghidra" }
func (Pipe) Skip(ctx *context.Context) bool { return len(ctx.Config.Ghidra) == 0 }

// Run the pipe.
func (Pipe) Run(ctx *context.Context) error {
	// g := semerrgroup.NewSkipAware(semerrgroup.New(ctx.Parallelism))
	var g errgroup.Group
	for _, ghi := range ctx.Config.Ghidra {
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
	return client.Run(ctx)
}

type Client struct {
	conf *config.Ghidra
	cmd  *exec.Cmd
}

func NewClient(conf *config.Ghidra) (*Client, error) {
	return &Client{conf: conf, cmd: exec.Command(conf.Path, conf.Args...)}, nil
}

func (c *Client) Run(ctx *context.Context) error {
	return c.cmd.Run()
}
