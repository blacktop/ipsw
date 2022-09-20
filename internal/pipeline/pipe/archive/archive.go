// Package archive implements the pipe interface with the intent of
// archiving and compressing the binaries, readme, and other artifacts. It
// also provides an Archive interface which represents an archiving format.
package archive

import (
	"sync"

	"github.com/apex/log"
	"github.com/blacktop/ipsw/internal/pipeline/artifact"
	"github.com/blacktop/ipsw/internal/pipeline/config"
	"github.com/blacktop/ipsw/internal/pipeline/context"
	"github.com/blacktop/ipsw/internal/pipeline/ids"
	"github.com/blacktop/ipsw/internal/pipeline/semerrgroup"
	"github.com/blacktop/ipsw/internal/pipeline/tmpl"
)

// const (
// 	defaultNameTemplateSuffix = `{{ .Version }}_{{ .Os }}_{{ .Arch }}{{ with .Arm }}v{{ . }}{{ end }}{{ with .Mips }}_{{ . }}{{ end }}{{ if not (eq .Amd64 "v1") }}{{ .Amd64 }}{{ end }}`
// 	defaultNameTemplate       = "{{ .ProjectName }}_" + defaultNameTemplateSuffix
// 	defaultBinaryNameTemplate = "{{ .Binary }}_" + defaultNameTemplateSuffix
// )

// nolint: gochecknoglobals
var lock sync.Mutex

// Pipe for archive.
type Pipe struct{}

func (Pipe) String() string {
	return "archives"
}

// Default sets the pipe defaults.
func (Pipe) Default(ctx *context.Context) error {
	ids := ids.New("archives")
	return ids.Validate()
}

// Run the pipe.
func (Pipe) Run(ctx *context.Context) error {
	g := semerrgroup.New(ctx.Parallelism)
	return g.Wait()
}

func doCreate(ctx *context.Context, arch config.Archive, binaries []*artifact.Artifact, format string, template *tmpl.Template) error {
	return nil
}

func wrapFolder(a config.Archive) string {
	switch a.WrapInDirectory {
	case "true":
		return a.NameTemplate
	case "false":
		return ""
	default:
		return a.WrapInDirectory
	}
}

func skip(ctx *context.Context, archive config.Archive, binaries []*artifact.Artifact) error {
	for _, binary := range binaries {
		name, err := tmpl.New(ctx).
			WithArtifact(binary, archive.Replacements).
			Apply(archive.NameTemplate)
		if err != nil {
			return err
		}
		finalName := name + artifact.ExtraOr(*binary, artifact.ExtraExt, "")
		log.WithField("binary", binary.Name).
			WithField("name", finalName).
			Info("skip archiving")
		ctx.Artifacts.Add(&artifact.Artifact{
			Type:    artifact.UploadableBinary,
			Name:    finalName,
			Path:    binary.Path,
			Goos:    binary.Goos,
			Goarch:  binary.Goarch,
			Goarm:   binary.Goarm,
			Gomips:  binary.Gomips,
			Goamd64: binary.Goamd64,
			Extra: map[string]interface{}{
				artifact.ExtraBuilds:   []*artifact.Artifact{binary},
				artifact.ExtraID:       archive.ID,
				artifact.ExtraFormat:   archive.Format,
				artifact.ExtraBinary:   binary.Name,
				artifact.ExtraReplaces: binaries[0].Extra[artifact.ExtraReplaces],
			},
		})
	}
	return nil
}
