package diff

import (
	"context"
	"fmt"

	mcmd "github.com/blacktop/ipsw/internal/commands/macho"
	"github.com/blacktop/ipsw/internal/diff/pipeline"
	"github.com/blacktop/ipsw/internal/diff/pipeline/handlers"
	"github.com/blacktop/ipsw/pkg/kernelcache"
)

// NewPipeline creates a new Diff using the pipeline architecture.
//
// This is the main entry point for diff operations. It creates a pipeline
// executor, registers all enabled handlers, runs the pipeline, and populates
// the Diff struct with results.
func NewPipeline(conf *Config) (*Diff, error) {
	// Create pipeline config
	pipelineCfg := &pipeline.Config{
		LaunchD:      conf.LaunchD,
		Firmware:     conf.Firmware,
		Features:     conf.Features,
		Files:        conf.Files,
		CStrings:     conf.CStrings,
		FuncStarts:   conf.FuncStarts,
		Entitlements: conf.Entitlements,
		AllowList:    conf.AllowList,
		BlockList:    conf.BlockList,
		PemDB:        conf.PemDB,
		Signatures:   conf.Signatures,
		Output:       conf.Output,
		Verbose:      conf.Verbose,
	}

	// Create executor
	exec := pipeline.NewExecutor(conf.IpswOld, conf.IpswNew, pipelineCfg)

	// Register KDKs if provided
	if len(conf.KDKs) == 2 {
		exec.OldCtx.KDK = conf.KDKs[0]
		exec.NewCtx.KDK = conf.KDKs[1]
	}

	// Register all handlers
	exec.RegisterAll(
		&handlers.KernelcacheHandler{},
		handlers.NewDSCHandler(),
		&handlers.LaunchdHandler{},
		&handlers.FirmwareHandler{},
		&handlers.IBootHandler{},
		&handlers.FeaturesHandler{},
		&handlers.FilesHandler{},
		&handlers.EntitlementsHandler{},
		&handlers.KDKHandler{},
		// TODO: add MachO handler when cache is implemented
	)

	// Execute pipeline
	ctx := context.Background()
	if err := exec.Execute(ctx); err != nil {
		return nil, fmt.Errorf("pipeline execution failed: %w", err)
	}

	// Create Diff struct and populate from results
	d := &Diff{
		Title: conf.Title,
		conf:  conf,
	}

	// If no title provided, generate one from versions
	if d.Title == "" {
		d.Title = fmt.Sprintf("%s (%s) .vs %s (%s)",
			exec.OldCtx.Version, exec.OldCtx.Build,
			exec.NewCtx.Version, exec.NewCtx.Build)
	}

	// Copy context info
	d.Old = Context{
		IPSWPath: exec.OldCtx.IPSWPath,
		Version:  exec.OldCtx.Version,
		Build:    exec.OldCtx.Build,
		KDK:      exec.OldCtx.KDK,
	}
	d.New = Context{
		IPSWPath: exec.NewCtx.IPSWPath,
		Version:  exec.NewCtx.Version,
		Build:    exec.NewCtx.Build,
		KDK:      exec.NewCtx.KDK,
	}

	// Map results to Diff fields
	if err := d.populateFromResults(exec); err != nil {
		return nil, fmt.Errorf("failed to populate results: %w", err)
	}

	return d, nil
}

// populateFromResults extracts handler results and populates the Diff struct.
func (d *Diff) populateFromResults(exec *pipeline.Executor) error {
	for result := range exec.Results() {
		r := exec.Results()[result]

		switch r.HandlerName {
		case "Kernelcache":
			if kexts, ok := r.Data.(*mcmd.MachoDiff); ok {
				d.Kexts = kexts
			}
			if path, ok := r.Metadata["old_path"].(string); ok {
				d.Old.Kernel.Path = path
			}
			if path, ok := r.Metadata["new_path"].(string); ok {
				d.New.Kernel.Path = path
			}
			if version, ok := r.Metadata["old_version"].(*kernelcache.Version); ok {
				d.Old.Kernel.Version = version
			}
			if version, ok := r.Metadata["new_version"].(*kernelcache.Version); ok {
				d.New.Kernel.Version = version
			}

		case "Launchd":
			if diff, ok := r.Data.(string); ok {
				d.Launchd = diff
			}

		case "Firmware":
			if firmwares, ok := r.Data.(*mcmd.MachoDiff); ok {
				d.Firmwares = firmwares
			}

		case "IBoot":
			if ibDiff, ok := r.Data.(*handlers.IBootDiff); ok {
				d.IBoot = &IBootDiff{
					Versions: ibDiff.Versions,
					New:      ibDiff.New,
					Removed:  ibDiff.Removed,
				}
			}

		case "Features":
			if fDiff, ok := r.Data.(*handlers.PlistDiff); ok {
				d.Features = &PlistDiff{
					New:     fDiff.New,
					Removed: fDiff.Removed,
					Updated: fDiff.Updated,
				}
			}

		case "Files":
			if fileDiff, ok := r.Data.(*handlers.FileDiff); ok {
				d.Files = &FileDiff{
					New:     fileDiff.New,
					Removed: fileDiff.Removed,
				}
			}

		case "Entitlements":
			if entDiff, ok := r.Data.(string); ok {
				d.Ents = entDiff
			}

		case "KDK":
			if kdkDiff, ok := r.Data.(string); ok {
				d.KDKs = kdkDiff
			}
			if name, ok := r.Metadata["old_kdk"].(string); ok {
				d.Old.KDK = name
			}
			if name, ok := r.Metadata["new_kdk"].(string); ok {
				d.New.KDK = name
			}

		case "DYLD Shared Cache":
			if dylibDiff, ok := r.Data.(*mcmd.MachoDiff); ok {
				d.Dylibs = dylibDiff
			}
			if webkit, ok := r.Metadata["webkit_old"].(string); ok {
				d.Old.Webkit = webkit
			}
			if webkit, ok := r.Metadata["webkit_new"].(string); ok {
				d.New.Webkit = webkit
			}

		// TODO: handle other result types as handlers are added

		default:
			// Unknown handler result - log it but don't fail
			if exec.Config.Verbose {
				fmt.Printf("Unknown handler result: %s\n", r.HandlerName)
			}
		}
	}

	return nil
}
