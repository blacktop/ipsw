//go:build sandbox

package diff

import (
	"errors"
	"fmt"
	"strings"

	"github.com/apex/log"
	"github.com/blacktop/go-macho"
	"github.com/blacktop/go-macho/pkg/fixupchains"
	"github.com/blacktop/go-macho/types"
	"github.com/blacktop/ipsw/pkg/sandbox"
	"github.com/blacktop/ipsw/pkg/sandbox/normalize"
)

const (
	maxSandboxDiffNormalizedNodes = 1000
	maxSandboxDiffOutputBytes     = 32 << 20
)

func (d *Diff) parseSandboxProfiles() (string, error) {
	oldDocs, err := collectSandboxProfileDocuments(&d.Old)
	if err != nil {
		return "", fmt.Errorf("old sandbox profiles: %w", err)
	}
	newDocs, err := collectSandboxProfileDocuments(&d.New)
	if err != nil {
		return "", fmt.Errorf("new sandbox profiles: %w", err)
	}
	if len(oldDocs) == 0 && len(newDocs) == 0 {
		return "", nil
	}
	return renderSandboxProfileDiffMarkdown(oldDocs, newDocs)
}

func collectSandboxProfileDocuments(ctx *Context) (sandboxProfileDocuments, error) {
	if ctx.Kernel.Path == "" {
		return nil, fmt.Errorf("kernelcache path is empty")
	}

	kernel, err := macho.Open(ctx.Kernel.Path)
	if err != nil {
		return nil, fmt.Errorf("failed to open kernelcache: %w", err)
	}
	defer kernel.Close()

	var fixups map[uint64]uint64
	if kernel.FileTOC.FileHeader.Type == types.MH_FILESET {
		fixups, err = buildSandboxDiffFixupMap(kernel)
		if err != nil {
			return nil, fmt.Errorf("failed to build fileset fixup map: %w", err)
		}
	}

	out := make(sandboxProfileDocuments)
	for _, source := range sandboxDiffSourceOrder {
		profiles, err := renderSandboxSourceProfiles(kernel, fixups, source)
		if err != nil {
			if isSandboxSourceUnavailable(err) {
				log.WithError(err).Debugf("skipping unavailable %s sandbox source", source)
				continue
			}
			return nil, fmt.Errorf("%s: %w", source, err)
		}
		if len(profiles) > 0 {
			out[source] = profiles
		}
	}

	return out, nil
}

func renderSandboxSourceProfiles(kernel *macho.File, fixups map[uint64]uint64, source string) (map[string]string, error) {
	conf := &sandbox.Config{Kernel: kernel}
	if fixups != nil {
		conf.Fixups = fixups
	}

	sbObj, err := sandbox.NewSandbox(conf)
	if err != nil {
		return nil, fmt.Errorf("failed to create sandbox parser: %w", err)
	}

	switch source {
	case sandboxDiffSourceCollection:
		if _, err := sbObj.GetCollectionData(); err != nil {
			return nil, fmt.Errorf("failed to load collection data: %w", err)
		}
		if err := sbObj.ParseSandboxCollection(); err != nil {
			return nil, fmt.Errorf("failed to parse collection data: %w", err)
		}
	case sandboxDiffSourceProtobox:
		if _, err := sbObj.GetProtoboxCollectionData(); err != nil {
			return nil, fmt.Errorf("failed to load protobox data: %w", err)
		}
		if err := sbObj.ParseProtoboxCollection(); err != nil {
			return nil, fmt.Errorf("failed to parse protobox data: %w", err)
		}
	case sandboxDiffSourceProfile:
		if _, err := sbObj.GetPlatformProfileData(); err != nil {
			return nil, fmt.Errorf("failed to load platform profile data: %w", err)
		}
		if err := sbObj.ParseSandboxProfile(); err != nil {
			return nil, fmt.Errorf("failed to parse platform profile data: %w", err)
		}
	default:
		return nil, fmt.Errorf("unsupported sandbox source %q", source)
	}

	return renderSandboxProfiles(sbObj, source)
}

func renderSandboxProfiles(sbObj *sandbox.Sandbox, source string) (map[string]string, error) {
	out := make(map[string]string, len(sbObj.Profiles))
	limit := maxSandboxDiffNormalizedNodes
	if source == sandboxDiffSourceProfile {
		// 0 disables the per-operation node budget. The platform profile is
		// one large standalone document, unlike collection profile entries.
		limit = 0
	}

	for idx, prof := range sbObj.Profiles {
		name := sandboxProfileDocumentName(source, prof, idx)
		formatted, diags, err := normalize.FormatCompilerSafeProfileWithDiagnostics(
			sbObj,
			prof,
			limit,
			maxSandboxDiffOutputBytes,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to render %s: %w", name, err)
		}
		if strings.TrimSpace(formatted) == "" {
			continue
		}
		if len(diags) > 0 {
			log.Warnf("%s/%s: %d sandbox operation(s) skipped due to budget limits",
				source, name, len(diags))
		}
		if _, exists := out[name]; exists {
			name = uniqueSandboxProfileDocumentName(out, name, idx)
		}
		out[name] = formatted
	}

	return out, nil
}

func sandboxProfileDocumentName(source string, prof sandbox.Profile, idx int) string {
	if prof.Name != "" {
		return prof.Name
	}
	if source == sandboxDiffSourceProfile {
		return "platform"
	}
	return fmt.Sprintf("profile_%03d", idx)
}

func uniqueSandboxProfileDocumentName(existing map[string]string, name string, idx int) string {
	candidate := fmt.Sprintf("%s#%d", name, idx)
	for suffix := 2; ; suffix++ {
		if _, exists := existing[candidate]; !exists {
			return candidate
		}
		candidate = fmt.Sprintf("%s#%d.%d", name, idx, suffix)
	}
}

func isSandboxSourceUnavailable(err error) bool {
	return errors.Is(err, sandbox.ErrSandboxSourceUnavailable)
}

func buildSandboxDiffFixupMap(kernel *macho.File) (map[uint64]uint64, error) {
	fixups := make(map[uint64]uint64)
	if !kernel.HasFixups() {
		return fixups, nil
	}
	dcf, err := kernel.DyldChainedFixups()
	if err != nil {
		return nil, err
	}
	for _, start := range dcf.Starts {
		if start.PageStarts == nil {
			continue
		}
		for _, fixup := range start.Fixups {
			if rebase, ok := fixup.(fixupchains.Rebase); ok {
				fixups[rebase.Raw()] = uint64(rebase.Offset()) + kernel.GetBaseAddress()
			}
		}
	}
	return fixups, nil
}
