package pipeline

import (
	"fmt"

	"github.com/blacktop/ipsw/internal/pipeline/context"
	"github.com/blacktop/ipsw/internal/pipeline/pipe/announce"
	"github.com/blacktop/ipsw/internal/pipeline/pipe/archive"
	"github.com/blacktop/ipsw/internal/pipeline/pipe/docker"
	"github.com/blacktop/ipsw/internal/pipeline/pipe/download"
	"github.com/blacktop/ipsw/internal/pipeline/pipe/extract"
	"github.com/blacktop/ipsw/internal/pipeline/pipe/publish"
)

// Job defines a pipe, which can be part of a pipeline (a series of pipes).
type Job interface {
	fmt.Stringer

	// Run the pipe
	Run(ctx *context.Context) error
}

// DownloadPipeline contains all build-related pipe implementations in order.
// nolint:gochecknoglobals
var DownloadPipeline = []Job{
	download.Pipe{}, // download firmwares
}

// Pipeline contains all pipe implementations in order.
// nolint: gochecknoglobals
var Pipeline = append(
	DownloadPipeline,
	extract.Pipe{},  // extract firmwares
	archive.Pipe{},  // archive in tar.gz, zip or binary (which does no archiving at all)
	docker.Pipe{},   // create and push docker images
	publish.Pipe{},  // publishes artifacts
	announce.Pipe{}, // announce releases
)
