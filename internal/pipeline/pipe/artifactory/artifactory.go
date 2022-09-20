// Package artifactory provides a Pipe that push to artifactory
package artifactory

import (
	"github.com/blacktop/ipsw/internal/pipeline/config"
	"github.com/blacktop/ipsw/internal/pipeline/context"
)

// Pipe for Artifactory.
type Pipe struct{}

func (Pipe) String() string                 { return "artifactory" }
func (Pipe) Skip(ctx *context.Context) bool { return len(ctx.Config.Artifactories) == 0 }

// Publish artifacts to artifactory.
//
// Docs: https://www.jfrog.com/confluence/display/RTF/Artifactory+REST+API#ArtifactoryRESTAPI-Example-DeployinganArtifact
func (Pipe) Publish(ctx *context.Context) error {
	// Check requirements for every instance we have configured.
	// If not fulfilled, we can skip this pipeline
	// for _, instance := range ctx.Config.Artifactories {
	// instance := instance
	// if skip := http.CheckConfig(ctx, &instance, "artifactory"); skip != nil {
	// return pipe.Skip(skip.Error())
	// }
	// }

	return doUpload(ctx, ctx.Config.Artifactories)
}

func doUpload(ctx *context.Context, uploads []config.Upload) error {

	return nil
}
