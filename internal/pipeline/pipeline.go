package pipeline

import (
	"context"
	"fmt"
)

// Job defines a pipe, which can be part of a pipeline (a series of pipes).
type Job interface {
	fmt.Stringer

	// Run the pipe
	Run(ctx *context.Context) error
}
