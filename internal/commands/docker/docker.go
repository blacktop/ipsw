package docker

import (
	"context"
	"fmt"
	"io"
	"os"

	"github.com/blacktop/ipsw/internal/utils"
	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/api/types/image"
	"github.com/docker/docker/api/types/mount"
	"github.com/docker/docker/api/types/network"
	"github.com/docker/docker/client"
	"github.com/docker/docker/pkg/stdcopy"
	"github.com/google/uuid"
	specs "github.com/opencontainers/image-spec/specs-go/v1"
)

type Client struct {
	ID         string       `yaml:"id,omitempty" json:"id,omitempty"`
	Image      string       `yaml:"image,omitempty" json:"image,omitempty"`
	Entrypoint []string     `yaml:"entrypoint,omitempty" json:"entrypoint,omitempty"`
	Cmd        []string     `yaml:"cmd,omitempty" json:"cmd,omitempty"`
	Env        []string     `yaml:"env,omitempty" json:"env,omitempty"`
	Mounts     []HostMounts `yaml:"mounts,omitempty" json:"mounts,omitempty"`
}

type HostMounts struct {
	Source   string
	Target   string
	ReadOnly bool
}

func NewClient(id, image string, entry []string, cmd []string, env []string, mounts []HostMounts) *Client {
	return &Client{
		ID:         id,
		Image:      image,
		Entrypoint: entry,
		Cmd:        cmd,
		Env:        env,
		Mounts:     mounts,
	}
}

func (c *Client) Run(ctx context.Context) error {
	cli, err := client.NewClientWithOpts(client.FromEnv, client.WithAPIVersionNegotiation())
	if err != nil {
		return fmt.Errorf("failed to create docker client: %w", err)
	}

	images, err := cli.ImageList(ctx, image.ListOptions{})
	if err != nil {
		return fmt.Errorf("failed to list images: %w", err)
	}
	found := false
	for _, image := range images {
		if utils.StrSliceContains(image.RepoTags, c.Image) {
			found = true
			break
		}
	}
	if !found {
		reader, err := cli.ImagePull(ctx, c.Image, image.PullOptions{
			// Platform: "linux/amd64",
		})
		if err != nil {
			return err
		}
		defer reader.Close()

		io.Copy(os.Stdout, reader)
	}

	var mounts []mount.Mount
	for _, m := range c.Mounts {
		mounts = append(mounts, mount.Mount{
			Type:     mount.TypeBind,
			Source:   m.Source,
			Target:   m.Target,
			ReadOnly: m.ReadOnly,
			BindOptions: &mount.BindOptions{
				CreateMountpoint: true,
			},
		})
	}

	resp, err := cli.ContainerCreate(ctx,
		&container.Config{
			Image:           c.Image,
			Entrypoint:      c.Entrypoint,
			Cmd:             c.Cmd,
			Env:             c.Env,
			Tty:             true,
			AttachStdout:    true,
			AttachStderr:    true,
			NetworkDisabled: true,
		}, &container.HostConfig{
			AutoRemove: true,
			// Resources: container.Resources{Memory: 1 << 30, MemorySwap: 1 << 30},
			Mounts: mounts,
		}, &network.NetworkingConfig{}, &specs.Platform{
			OS:           "linux",
			Architecture: "amd64",
		}, "ipsw-idapro-"+uuid.New().String())
	if err != nil {
		return fmt.Errorf("failed to create container: %w", err)
	}

	if err := cli.ContainerStart(ctx, resp.ID, container.StartOptions{}); err != nil {
		return fmt.Errorf("failed to start container: %w", err)
	}

	go func() {
		out, err := cli.ContainerLogs(ctx, resp.ID, container.LogsOptions{
			ShowStdout: true,
			ShowStderr: true,
			Follow:     true,
			Timestamps: false,
		})
		if err != nil {
			panic(fmt.Errorf("failed to get container logs: %w", err))
		}

		stdcopy.StdCopy(os.Stdout, os.Stderr, out)
	}()

	statusCh, errCh := cli.ContainerWait(ctx, resp.ID, container.WaitConditionNotRunning)
	select {
	case err := <-errCh:
		if err != nil {
			return fmt.Errorf("error waiting for container: %w", err)
		}
	case <-statusCh:
	}

	return nil
}
