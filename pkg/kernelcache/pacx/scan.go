package pacx

// This file is the orchestration entry point that turns an opened kernelcache
// into resolved authenticated virtual-call edges. It builds the vtable-side
// (offset, pac) index via the cpp scanner, scans every function body for
// authenticated virtual calls, attributes each call site to its fileset image
// and caller symbol, and joins the two sides.

import (
	"fmt"
	"io"
	"sort"

	"github.com/blacktop/go-macho"
	mtypes "github.com/blacktop/go-macho/types"
	"github.com/blacktop/ipsw/pkg/kernelcache/cpp"
)

// ScanConfig controls a kernelcache PAC-xref scan.
type ScanConfig struct {
	// Name is the kernelcache basename recorded in the index metadata.
	Name string
	// Entries restricts class discovery to the named bundles (empty = all).
	Entries []string
	// Window bounds the call-site backward register walk (<= 0 uses the default).
	Window int
	// IncludeUnresolved keeps call sites with zero matching candidates.
	IncludeUnresolved bool
	// Stderr receives progress lines when non-nil.
	Stderr io.Writer
}

// imageFunc is one function body tagged with the fileset image it came from.
type imageFunc struct {
	image string
	body  FuncBody
}

// ScanKernelcache resolves authenticated virtual calls in root and returns the
// sorted PacRecords. It builds the vtable index (cpp discovery -> BuildIndex),
// scans function bodies for call sites, attributes each to its image and caller,
// and joins the two.
func ScanKernelcache(root *macho.File, conf ScanConfig) ([]PacRecord, error) {
	if root == nil {
		return nil, fmt.Errorf("nil macho file")
	}
	scanner := cpp.NewScanner(root, cpp.Config{Entries: conf.Entries})
	classes, err := scanner.Scan()
	if err != nil {
		return nil, fmt.Errorf("scan classes: %w", err)
	}
	progress(conf.Stderr, "pacx: discovered %d classes\n", len(classes))

	index := BuildIndex(Meta{Kernelcache: conf.Name}, scanner.BuildNamedMethodTables(classes))
	progress(conf.Stderr, "pacx: indexed %d authenticated slots (%d forward keys)\n", len(index.Slots), len(index.Forward))

	imageFuncs, err := collectImageFuncs(root)
	if err != nil {
		return nil, err
	}
	funcs := make([]FuncBody, len(imageFuncs))
	imageByStart := make(map[uint64]string, len(imageFuncs))
	for i, f := range imageFuncs {
		funcs[i] = f.body
		imageByStart[f.body.Addr] = f.image
	}

	csi := BuildCallSiteIndex(funcs, conf.Window)
	records := Join(index, csi, siteAttributor(scanner, imageByStart), conf.IncludeUnresolved)
	progress(conf.Stderr, "pacx: emitted %d resolved edges\n", len(records))
	return records, nil
}

// siteAttributor builds the per-call-site metadata resolver: the caller symbol
// and fileset image of the containing function, and the auth mnemonic taken
// straight from the call's already-decoded key bit. Caller symbols are memoized
// because one function commonly hosts many resolved call sites.
func siteAttributor(scanner *cpp.Scanner, imageByStart map[uint64]string) SiteAttributor {
	symByFunc := make(map[uint64]string)
	return func(site CallSite) SiteMeta {
		sym, ok := symByFunc[site.CallerFuncAddr]
		if !ok {
			sym = scanner.SymbolName(site.CallerFuncAddr)
			symByFunc[site.CallerFuncAddr] = sym
		}
		return SiteMeta{
			CallerSymbol: sym,
			Image:        imageByStart[site.CallerFuncAddr],
			Auth:         authForKeyB(site.KeyB),
		}
	}
}

// authForKeyB maps a register-form authenticated call's key bit to its mnemonic.
func authForKeyB(keyB bool) string {
	if keyB {
		return "blrab"
	}
	return "blraa"
}

// collectImageFuncs gathers every function body across the kernelcache, tagged
// with its fileset image. For a fileset kernelcache the bodies come from each
// fileset entry; otherwise from the single Mach-O.
func collectImageFuncs(root *macho.File) ([]imageFunc, error) {
	if root.FileTOC.FileHeader.Type == mtypes.MH_FILESET {
		return collectFilesetImageFuncs(root.FileSets(), root.GetFileSetFileByName, funcBodiesFor)
	}
	return funcBodiesFor(kernelImageName, root)
}

const kernelImageName = "com.apple.kernel"

func collectFilesetImageFuncs(entries []*macho.FilesetEntry, open func(string) (*macho.File, error), collect func(string, *macho.File) ([]imageFunc, error)) ([]imageFunc, error) {
	var out []imageFunc
	for _, entry := range entries {
		m, err := open(entry.EntryID)
		if err != nil {
			continue
		}
		bodies, err := collect(entry.EntryID, m)
		if err != nil {
			return nil, err
		}
		out = append(out, bodies...)
	}
	return out, nil
}

// funcBodiesFor reads every function body in m, tagging each with image.
func funcBodiesFor(image string, m *macho.File) ([]imageFunc, error) {
	funcs, err := functionsForScan(m.GetFunctions(), m.GenerateFunctionStarts)
	if err != nil {
		return nil, fmt.Errorf("collect functions for %s: %w", image, err)
	}
	out := make([]imageFunc, 0, len(funcs))
	for _, fn := range funcs {
		data, err := m.GetFunctionData(fn)
		if err != nil {
			continue
		}
		out = append(out, imageFunc{image: image, body: FuncBody{Addr: fn.StartAddr, Code: data}})
	}
	return out, nil
}

func functionsForScan(funcs []mtypes.Function, generate func() ([]mtypes.Function, error)) ([]mtypes.Function, error) {
	if len(funcs) == 0 {
		generated, err := generate()
		if err != nil {
			return nil, fmt.Errorf("generate function starts: %w", err)
		}
		funcs = generated
	}
	// Copy before sorting: m.GetFunctions() returns go-macho's cached slice, and
	// sorting in place would mutate shared Mach-O state (cf. ent/xrefs sortedFunctions).
	out := append([]mtypes.Function(nil), funcs...)
	sort.Slice(out, func(i, j int) bool {
		return out[i].StartAddr < out[j].StartAddr
	})
	return out, nil
}

func progress(w io.Writer, format string, args ...any) {
	if w != nil {
		fmt.Fprintf(w, format, args...)
	}
}
