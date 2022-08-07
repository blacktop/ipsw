// Package docker contains the docker pipe.
package docker

import (
	"fmt"
	"io"
	"os"

	"github.com/apex/log"
	"github.com/blacktop/ipsw/internal/config"
	"github.com/blacktop/ipsw/internal/context"
	"github.com/blacktop/ipsw/internal/pipe"
	"golang.org/x/sync/errgroup"

	"github.com/docker/docker/api/types"
	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/client"
	"github.com/docker/docker/pkg/stdcopy"
)

// Pipe that runs dockerized pipelines.
type Pipe struct{}

func (Pipe) String() string                 { return "docker pipes" }
func (Pipe) Skip(ctx *context.Context) bool { return len(ctx.Config.Dockers) == 0 }

// Run the pipe.
func (Pipe) Run(ctx *context.Context) error {
	// g := semerrgroup.NewSkipAware(semerrgroup.New(ctx.Parallelism))
	var g errgroup.Group
	for _, docker := range ctx.Config.Dockers {
		docker := docker
		g.Go(func() error {
			log.WithField("docker", docker).Debug("running docker pipe")
			return dockerRun(ctx, docker)
		})
	}
	if err := g.Wait(); err != nil {
		if pipe.IsSkip(err) {
			return err
		}
		return fmt.Errorf("docker pipe failed: %w", err)
	}
	return nil
}

func dockerRun(ctx *context.Context, docker config.Docker) error {
	cli, err := client.NewClientWithOpts(client.FromEnv, client.WithAPIVersionNegotiation())
	if err != nil {
		return err
	}

	reader, err := cli.ImagePull(ctx, docker.Image, types.ImagePullOptions{})
	if err != nil {
		return err
	}
	defer reader.Close()

	io.Copy(os.Stdout, reader)

	resp, err := cli.ContainerCreate(ctx, &container.Config{
		Image: docker.Image,
		Cmd:   docker.Cmd,
		Tty:   false,
	}, nil, nil, nil, "")
	if err != nil {
		return err
	}

	if err := cli.ContainerStart(ctx, resp.ID, types.ContainerStartOptions{}); err != nil {
		return err
	}

	statusCh, errCh := cli.ContainerWait(ctx, resp.ID, container.WaitConditionNotRunning)
	select {
	case err := <-errCh:
		if err != nil {
			return err
		}
	case <-statusCh:
	}

	out, err := cli.ContainerLogs(ctx, resp.ID, types.ContainerLogsOptions{ShowStdout: true})
	if err != nil {
		return err
	}

	stdcopy.StdCopy(os.Stdout, os.Stderr, out) // TODO: does this exit?

	return nil
}
