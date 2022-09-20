// Package idapro contains the IDA Pro pipe.
package idapro

import (
	"fmt"
	"os/exec"
	"path/filepath"
	"runtime"

	"github.com/apex/log"
	"github.com/blacktop/ipsw/internal/pipeline/config"
	"github.com/blacktop/ipsw/internal/pipeline/context"
	"github.com/blacktop/ipsw/internal/pipeline/pipe"
	"golang.org/x/sync/errgroup"
)

const (
	darwinPath  = "/Applications/IDA Pro */ida64.app/Contents/MacOS/"
	linuxPath   = ""
	windowsPath = ""
)

// Pipe that runs dockerized pipelines.
type Pipe struct{}

func (Pipe) String() string                 { return "ida pro" }
func (Pipe) Skip(ctx *context.Context) bool { return len(ctx.Config.IDA) == 0 }

// Run the pipe.
func (Pipe) Run(ctx *context.Context) error {
	// g := semerrgroup.NewSkipAware(semerrgroup.New(ctx.Parallelism))
	var g errgroup.Group
	for _, ida := range ctx.Config.IDA {
		ida := ida
		g.Go(func() error {
			log.WithField("ida pro", ida).Debug("running IDA Pro pipe")
			return runIDAPro(ctx, ida)
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

func runIDAPro(ctx *context.Context, conf config.IDA) error {
	client, err := NewClient(&conf)
	if err != nil {
		return err
	}
	return client.Run(ctx)
}

type Client struct {
	conf *config.IDA
	cmd  *exec.Cmd
}

func NewClient(conf *config.IDA) (*Client, error) {
	var path string
	switch runtime.GOOS {
	case "darwin":
		path = darwinPath
	case "linux":
		path = linuxPath
	case "windows":
		path = windowsPath
	default:
		return nil, fmt.Errorf("unsupported OS: %s", runtime.GOOS)
	}

	executable := filepath.Join(path, "idat64")
	if conf.EnableGUI {
		executable = filepath.Join(path, "ida64")
	}

	args := []string{}
	if conf.AutoAnalyze {
		args = append(args, "-a-")
	} else {
		args = append(args, "-a")
	}
	if !conf.EnableGUI || conf.AutoAccept {
		args = append(args, "-A")
	}
	if conf.TempDatabase {
		args = append(args, "-DABANDON_DATABASE=YES")
	}
	if conf.DeleteDB {
		args = append(args, "-c")
	}
	if conf.LogFile != "" {
		args = append(args, fmt.Sprintf("-L=\"%s\"", conf.Compiler))
	}
	if conf.Compiler != "" {
		args = append(args, fmt.Sprintf("-C=\"%s\"", conf.Compiler))
	}
	if conf.Processor != "" {
		args = append(args, fmt.Sprintf("-p=\"%s\"", conf.Processor))
	}
	if len(conf.ScriptArgs) > 0 {
		quoted := []string{conf.ScriptArgs[0]}
		for _, arg := range conf.ScriptArgs[1:] {
			quoted = append(quoted, fmt.Sprintf(`"%s"`, arg))
		}
		// Doesn't really work, probably some escaping issue :/
		// args = append(args, quoteArg("S", strings.Join(conf.ScriptArgs[:], " ")))
		args = append(args, fmt.Sprintf("-OIDAPython:run_script=%s", conf.ScriptArgs[0]))
	}
	if len(conf.PluginArgs) > 0 {
		if len(conf.ScriptArgs) > 0 {
			origArgs := conf.PluginArgs
			conf.PluginArgs = conf.ScriptArgs
			conf.PluginArgs = append(conf.PluginArgs, origArgs...)
		} else {
			conf.PluginArgs = append([]string{"no_script"}, conf.PluginArgs...)
		}
		for _, arg := range conf.PluginArgs[:] {
			args = append(args, fmt.Sprintf("-Oemmu:%s", arg))
		}
	}
	if conf.FileType != "" {
		args = append(args, fmt.Sprintf("-T=\"%s\"", conf.FileType))
	}
	args = append(args, conf.ExtraArgs...)
	args = append(args, conf.InputFile)
	return &Client{conf: conf, cmd: exec.Command(executable, args...)}, nil
}

func (c *Client) Run(ctx *context.Context) error {
	return c.cmd.Run()
}
