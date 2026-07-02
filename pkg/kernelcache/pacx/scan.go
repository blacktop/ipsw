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
	"github.com/blacktop/ipsw/pkg/xref"
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
	bodyByStart := make(map[uint64]imageFunc, len(imageFuncs))
	for i, f := range imageFuncs {
		funcs[i] = f.body
		bodyByStart[f.body.Addr] = f
	}

	csi := BuildCallSiteIndex(funcs, conf.Window)
	records := Join(index, csi, siteAttributor(scanner, bodyByStart), conf.IncludeUnresolved)
	progress(conf.Stderr, "pacx: emitted %d resolved edges\n", len(records))
	return records, nil
}

// siteAttributor builds the per-call-site metadata resolver: image and caller
// symbol from the containing function, and the auth mnemonic from the call
// instruction word.
func siteAttributor(scanner *cpp.Scanner, bodyByStart map[uint64]imageFunc) SiteAttributor {
	return func(site CallSite) SiteMeta {
		meta := SiteMeta{CallerSymbol: scanner.SymbolName(site.CallerFuncAddr)}
		f, ok := bodyByStart[site.CallerFuncAddr]
		if !ok {
			return meta
		}
		meta.Image = f.image
		off := site.Addr - f.body.Addr
		if off+4 <= uint64(len(f.body.Code)) {
			meta.Auth = authMnemonic(f.body.Code[off:off+4], site.Addr)
		}
		return meta
	}
}

// authMnemonic decodes a single call-site instruction word and reports "blraa"
// or "blrab", or an empty string when the word is not a register-form
// authenticated call.
func authMnemonic(word []byte, addr uint64) string {
	instrs := xref.Decode(word, addr)
	if len(instrs) == 0 {
		return ""
	}
	call, ok := xref.DecodeAuthCallReg(&instrs[0].Inst)
	if !ok {
		return ""
	}
	if call.KeyB {
		return "blrab"
	}
	return "blraa"
}

// collectImageFuncs gathers every function body across the kernelcache, tagged
// with its fileset image. For a fileset kernelcache the bodies come from each
// fileset entry; otherwise from the single Mach-O.
func collectImageFuncs(root *macho.File) ([]imageFunc, error) {
	if root.FileTOC.FileHeader.Type == mtypes.MH_FILESET {
		var out []imageFunc
		for _, entry := range root.FileSets() {
			m, err := root.GetFileSetFileByName(entry.EntryID)
			if err != nil {
				continue
			}
			bodies, err := funcBodiesFor(entry.EntryID, m)
			if err != nil {
				return nil, err
			}
			out = append(out, bodies...)
		}
		return out, nil
	}
	return funcBodiesFor(kernelImageName, root)
}

const kernelImageName = "com.apple.kernel"

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
	sort.Slice(funcs, func(i, j int) bool {
		return funcs[i].StartAddr < funcs[j].StartAddr
	})
	return funcs, nil
}

func progress(w io.Writer, format string, args ...any) {
	if w != nil {
		fmt.Fprintf(w, format, args...)
	}
}
