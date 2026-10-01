package syms

import (
	"archive/zip"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/blacktop/go-macho"
	"github.com/blacktop/ipsw/internal/commands/mount"
	"github.com/blacktop/ipsw/internal/utils"
	"github.com/blacktop/ipsw/pkg/info"
	"github.com/blacktop/ipsw/pkg/signature"
)

// ValidateFactsSelection validates an opt-in board collection before the caller
// creates its output. Info must contain the full, unfiltered BuildManifest.
func ValidateFactsSelection(cfg *JSONLConfig) error {
	if cfg.FactsBoards == nil {
		return nil
	}
	if err := ValidateFactsBoardsOptions(cfg); err != nil {
		return err
	}
	collection, err := newFactsCollection(cfg, cfg.Info, factsSourceIdentity{})
	if err != nil {
		return err
	}
	return validateFactsArchive(cfg.IPSW, factsComponentPlan(collection))
}

// ValidateFactsBoardsOptions rejects option combinations that a board-subset
// collection cannot honor. It does no I/O, so callers can run it first.
func ValidateFactsBoardsOptions(cfg *JSONLConfig) error {
	if cfg.FactsBoards != nil && (!cfg.Facts || cfg.Device != "") {
		return errors.New("--facts-boards requires --facts and cannot be combined with --device")
	}
	return nil
}

func factsBoardSelection(cfg *JSONLConfig, inf *info.Info) (factsManifestSelection, error) {
	if len(cfg.FactsBoards) == 0 || len(cfg.FactsBoards) > 128 {
		return factsManifestSelection{}, fmt.Errorf("--facts-boards requires between 1 and 128 boards")
	}
	if inf == nil || inf.Plists == nil || inf.Plists.BuildManifest == nil {
		return factsManifestSelection{}, fmt.Errorf("missing BuildManifest for facts board selection")
	}
	boards := make([]string, 0, len(cfg.FactsBoards))
	for _, board := range cfg.FactsBoards {
		board = strings.ToLower(strings.TrimSpace(board))
		if board == "" || slices.Contains(boards, board) {
			return factsManifestSelection{}, fmt.Errorf("empty or duplicate facts board %q", board)
		}
		boards = append(boards, board)
	}
	slices.Sort(boards)
	selection := factsSelection("", inf)
	unselected := func(identity factsManifestIdentity) bool {
		return !slices.Contains(boards, strings.ToLower(identity.Board))
	}
	selection.Identities = slices.DeleteFunc(selection.Identities, unselected)
	selection.Devices, selection.Boards = nil, nil
	for idx := range selection.Identities {
		identity := &selection.Identities[idx]
		identity.Board = strings.ToLower(identity.Board)
		selection.Devices = append(selection.Devices, identity.Device)
		selection.Boards = append(selection.Boards, identity.Board)
	}
	slices.SortFunc(selection.Identities, func(a, b factsManifestIdentity) int {
		return strings.Compare(identitySortKey(a), identitySortKey(b))
	})
	selection.Devices = sortedNonemptyUnique(selection.Devices)
	selection.Boards = sortedNonemptyUnique(selection.Boards)
	if !slices.Equal(boards, selection.Boards) {
		return factsManifestSelection{}, fmt.Errorf(
			"unknown facts board in requested subset %v (matched %v)", boards, selection.Boards)
	}
	// A present component with no path is not equivalent to an absent volume.
	for _, identity := range inf.Plists.BuildIdentities {
		if !slices.Contains(boards, strings.ToLower(identity.Info.DeviceClass)) {
			continue
		}
		for _, name := range manifestComponentNames {
			if name == "OS" && strings.Contains(identity.Info.Variant, "Recovery") {
				continue
			}
			if component, ok := identity.Manifest[name]; ok {
				componentPath, valid := manifestPath(component)
				if !valid || !filepath.IsLocal(componentPath) {
					return factsManifestSelection{}, fmt.Errorf("board %q has invalid %s component path %q",
						identity.Info.DeviceClass, name, componentPath)
				}
			}
		}
	}
	for _, board := range boards {
		boardSelection := factsManifestSelection{}
		for _, identity := range selection.Identities {
			if identity.Board == board {
				boardSelection.Identities = append(boardSelection.Identities, identity)
			}
		}
		for _, name := range manifestComponentNames {
			components := componentPaths(boardSelection, name)
			if name != "KernelCache" && len(components) > 1 {
				return factsManifestSelection{}, fmt.Errorf(
					"board %q has ambiguous %s component paths %v", board, name, components)
			}
			if name == "KernelCache" && cfg.Kernel {
				if len(components) == 0 {
					return factsManifestSelection{}, fmt.Errorf("board %q has no KernelCache component", board)
				}
				namespaces := make(map[string]bool)
				for _, component := range components {
					namespace, err := kernelFactsNamespace(component)
					if err != nil {
						return factsManifestSelection{}, err
					}
					if namespaces[namespace] {
						return factsManifestSelection{}, fmt.Errorf(
							"board %q has ambiguous kernel namespace %q", board, namespace)
					}
					namespaces[namespace] = true
				}
			}
		}
		hasSystem := len(componentPaths(boardSelection, "OS")) != 0 ||
			len(componentPaths(boardSelection, "Cryptex1,SystemOS")) != 0
		if (cfg.DSC || cfg.FileSystem) && !hasSystem {
			return factsManifestSelection{}, fmt.Errorf("board %q has no SystemOS or OS component", board)
		}
	}
	return selection, nil
}

// SystemOS fallback belongs to each board, not to the union of boards. A newer
// board's cryptex must not hide an older board's filesystem cache.
func factsSystemComponents(selection factsManifestSelection) []string {
	var components []string
	for _, board := range selection.Boards {
		boardSelection := factsManifestSelection{}
		for _, identity := range selection.Identities {
			if identity.Board == board {
				boardSelection.Identities = append(boardSelection.Identities, identity)
			}
		}
		paths := componentPaths(boardSelection, "Cryptex1,SystemOS")
		if len(paths) == 0 {
			paths = componentPaths(boardSelection, "OS")
		}
		components = append(components, paths...)
	}
	return sortedNonemptyUnique(components)
}

type factsComponentScan struct {
	path    string
	kernel  bool
	dsc     bool
	volumes []string
}

func factsComponentPlan(c *factsCollection) []factsComponentScan {
	var plan []factsComponentScan
	for _, row := range c.coverage {
		if row.Status != "unavailable" || row.Reason != "selected collection did not finish" {
			continue
		}
		for _, component := range row.ComponentPaths {
			idx := slices.IndexFunc(plan, func(entry factsComponentScan) bool {
				return entry.path == component
			})
			if idx < 0 {
				plan = append(plan, factsComponentScan{path: component})
				idx = len(plan) - 1
			}
			entry := &plan[idx]
			switch {
			case row.Volume == "kernelcache":
				entry.kernel = true
			case row.Family == "dsc":
				entry.dsc = true
			default:
				if !slices.Contains(entry.volumes, row.Volume) {
					entry.volumes = append(entry.volumes, row.Volume)
				}
			}
		}
	}
	slices.SortFunc(plan, func(a, b factsComponentScan) int { return strings.Compare(a.path, b.path) })
	return plan
}

func validateFactsArchive(ipswPath string, plan []factsComponentScan) error {
	zr, err := zip.OpenReader(ipswPath)
	if err != nil {
		return err
	}
	defer zr.Close()
	for _, component := range plan {
		if _, err := mount.ExactArchiveMember(&zr.Reader, component.path); err != nil {
			return err
		}
		if component.kernel && (component.dsc || len(component.volumes) != 0) {
			return fmt.Errorf("component %q is both a kernelcache and disk image", component.path)
		}
	}
	return nil
}

// Explicit operations let tests exercise the real component dispatch and facts
// callbacks without attaching synthetic images or mutating host mount state.
type factsScanOperations struct {
	kernel func(*factsCollection) error
	mount  func(string, func(string) error) error
	dsc    func(string, scanVisitor, scanFactsVisitor) error
	machos func(string, string, scanVisitor, scanFactsVisitor) error
}

func scanFactsComponents(cfg *scanConfig, visit scanVisitor) error {
	// Every kernel component shares one parse of the signatures directory.
	var sigs []signature.Symbolicator
	if cfg.Kernel {
		var err error
		if sigs, err = parseKernelSignatures(cfg.SigsDir); err != nil {
			return err
		}
	}
	return runFactsComponents(cfg.Collection, visit, cfg.Facts, factsScanOperations{
		kernel: func(collection *factsCollection) error {
			return scanKernels(cfg.IPSW, sigs, "", cfg.Info, collection, visit, cfg.Facts)
		},
		mount: func(component string, scan func(string) error) error {
			acquire := func(dir string) (*mount.Context, error) {
				mountCfg := &mount.Config{ExtractDir: dir, PemDB: cfg.PemDB}
				return mount.DmgComponentInIPSW(cfg.IPSW, component, mountCfg)
			}
			return mountFactsComponent(acquire, (*mount.Context).Unmount, scan)
		},
		dsc: scanDSCsInMount, machos: scanMachosInMount,
	})
}

// mountFactsComponent scans one component image extracted into a private
// directory, then detaches it and removes the directory unless the image may
// still be attached.
func mountFactsComponent(
	acquire func(dir string) (*mount.Context, error),
	unmount func(*mount.Context) error,
	scan func(root string) error,
) (retErr error) {
	dir, err := os.MkdirTemp("", "ipsw-facts-component-")
	if err != nil {
		return err
	}
	ctx, err := acquire(dir)
	if err != nil {
		return errors.Join(err, os.RemoveAll(dir))
	}
	if ctx.AlreadyMounted {
		// A borrowed mount is never detached, so its backing image must stay.
		return fmt.Errorf("private component image %s is already mounted at %s; leaving %s in place",
			ctx.DmgPath, ctx.MountPoint, dir)
	}
	defer func() {
		err := unmount(ctx)
		retErr = errors.Join(retErr, err)
		if !errors.Is(err, utils.ErrMountCleanup) {
			retErr = errors.Join(retErr, os.RemoveAll(dir))
		}
	}()
	return scan(ctx.MountPoint)
}

func runFactsComponents(
	c *factsCollection, visit scanVisitor, facts scanFactsVisitor, ops factsScanOperations,
) error {
	for _, component := range factsComponentPlan(c) {
		if component.kernel {
			// Restrict each extraction to this exact path while retaining all
			// identities for device-derived kernel presentation names.
			one := *c
			one.start.Selection.Identities = slices.Clone(c.start.Selection.Identities)
			for idx := range one.start.Selection.Identities {
				identity := &one.start.Selection.Identities[idx]
				otherKernel := func(value factsManifestComponent) bool {
					return value.Name == "KernelCache" && value.Path != component.path
				}
				identity.Components = slices.DeleteFunc(slices.Clone(identity.Components), otherKernel)
			}
			if err := ops.kernel(&one); err != nil {
				return fmt.Errorf("scan kernel component %q: %w", component.path, err)
			}
			continue
		}
		err := ops.mount(component.path, func(root string) error {
			image := func(img *scanImage) error {
				copy := *img
				copy.ComponentPath = component.path
				return visit(&copy)
			}
			contextFacts := func(img *scanImage, m *macho.File) error {
				copy := *img
				copy.ComponentPath = component.path
				return facts(&copy, m)
			}
			if component.dsc {
				if err := ops.dsc(root, image, contextFacts); err != nil {
					return err
				}
			}
			if len(component.volumes) > 0 {
				fanout := func(img *scanImage, m *macho.File) error {
					for _, volume := range component.volumes {
						copy := *img
						copy.VolumeLabel = volume
						if err := contextFacts(&copy, m); err != nil {
							return err
						}
					}
					return nil
				}
				return ops.machos(root, component.volumes[0], image, fanout)
			}
			return nil
		})
		if err != nil {
			return fmt.Errorf("scan disk component %q: %w", component.path, err)
		}
	}
	for idx := range c.coverage {
		row := &c.coverage[idx]
		if row.Status == "unavailable" && row.Reason == "selected collection did not finish" {
			row.Status, row.Reason = "successful", ""
		}
	}
	return nil
}
