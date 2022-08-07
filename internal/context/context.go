// Package context provides ipsw context which is passed through the
// pipeline.
//
// The context extends the standard library context and add a few more
// fields and other things, so pipes can gather data provided by previous
// pipes without really knowing each other.
package context

import (
	stdctx "context"
	"os"
	"runtime"
	"strings"
	"time"

	"github.com/blacktop/ipsw/internal/config"
)

// Env is the environment variables.
type Env map[string]string

// Copy returns a copy of the environment.
func (e Env) Copy() Env {
	out := Env{}
	for k, v := range e {
		out[k] = v
	}
	return out
}

// Strings returns the current environment as a list of strings, suitable for
// os executions.
func (e Env) Strings() []string {
	result := make([]string, 0, len(e))
	for k, v := range e {
		result = append(result, k+"="+v)
	}
	return result
}

// Context carries along some data through the pipes.
type Context struct {
	stdctx.Context
	Config config.Job
	Env    Env
	Date   time.Time
	// Artifacts          artifact.Artifacts
	Version      string
	SkipDownload bool
	SkipPublish  bool
	SkipAnnounce bool
	RmIPSW       bool
	Parallelism  int
	Runtime      Runtime
}

type Runtime struct {
	Goos   string
	Goarch string
}

// New context.
func New(config config.Job) *Context {
	return Wrap(stdctx.Background(), config)
}

// NewWithTimeout new context with the given timeout.
func NewWithTimeout(config config.Job, timeout time.Duration) (*Context, stdctx.CancelFunc) {
	ctx, cancel := stdctx.WithTimeout(stdctx.Background(), timeout)
	return Wrap(ctx, config), cancel
}

// Wrap wraps an existing context.
func Wrap(ctx stdctx.Context, config config.Job) *Context {
	return &Context{
		Context:     ctx,
		Config:      config,
		Env:         ToEnv(append(os.Environ(), config.Env...)),
		Parallelism: 4,
		// Artifacts:   artifact.New(),
		Date: time.Now(),
		Runtime: Runtime{
			Goos:   runtime.GOOS,
			Goarch: runtime.GOARCH,
		},
	}
}

// ToEnv converts a list of strings to an Env (aka a map[string]string).
func ToEnv(env []string) Env {
	r := Env{}
	for _, e := range env {
		k, v, ok := strings.Cut(e, "=")
		if !ok || k == "" {
			continue
		}
		r[k] = v
	}
	return r
}
