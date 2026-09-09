package diff

import (
	"fmt"

	"github.com/blacktop/ipsw/pkg/info"
	"github.com/blacktop/ipsw/pkg/kernelcache"
	"golang.org/x/exp/maps"
)

// selectDiffDevice permits an unmatched device's shared-SystemOS baseline only
// when its kernel is shared too. A DSC-only consumer need not impose this rule.
func selectDiffDevice(inf *info.Info, device string) (*info.Info, error) {
	if selected, err := inf.ForDevice(device); err == nil {
		return selected.SelectDevice("")
	}
	selected, err := inf.SelectDeviceOrSharedSystem(device)
	if err != nil {
		return nil, err
	}
	var kernel string
	for _, identity := range selected.Plists.BuildIdentities {
		component, ok := identity.Manifest["KernelCache"]
		if !ok {
			continue
		}
		path, ok := component.Info["Path"].(string)
		if !ok || path == "" {
			return nil, fmt.Errorf("cannot use shared SystemOS for absent device %q: invalid kernelcache path", device)
		}
		if kernel != "" && kernel != path {
			return nil, fmt.Errorf("cannot use shared SystemOS for absent device %q: multiple kernelcache paths (%s, %s)", device, kernel, path)
		}
		kernel = path
	}
	if kernel == "" {
		return nil, fmt.Errorf("cannot use shared SystemOS for absent device %q: no kernelcache", device)
	}
	return selected, nil
}

// ipswVolumeOrderMachos is the volume order the *InIPSW walkers enumerate:
// FileSystem, SystemOS, AppOS, ExclaveOS. machos/files/plists/localizations
// share it.
var ipswVolumeOrderMachos = []string{"fs", "sys", "app", "exc"}

type ipswVolumeFileSession interface {
	Root(string) (string, error)
	Release(string) error
}

// volumeResolves reports whether the selected IPSW metadata resolves the given
// OS volume without a getter error. It does not fall back from sys to fs.
func volumeResolves(inf *info.Info, typ string) bool {
	if inf == nil {
		return false
	}
	var err error
	switch typ {
	case "fs":
		_, err = inf.GetFileSystemOsDmg()
	case "sys":
		_, err = inf.GetSystemOsDmg()
	case "app":
		_, err = inf.GetAppOsDmg()
	case "exc":
		_, err = inf.GetExclaveOSDmg()
	default:
		return false
	}
	return err == nil
}

// volumeLabel is the DMG label ForEachFileInIPSW emits (note the lowercase
// "filesystem"); used by parseFiles.
func volumeLabel(typ string) string {
	switch typ {
	case "fs":
		return "filesystem"
	case "sys":
		return "SystemOS"
	case "app":
		return "AppOS"
	case "exc":
		return "ExclaveOS"
	}
	return typ
}

// volumeListDMGLabel is the DMG label search.ListDMGs uses (capital
// "FileSystem"); used by parseLocalizations, whose keys embed this name.
func volumeListDMGLabel(typ string) string {
	if typ == "fs" {
		return "FileSystem"
	}
	return volumeLabel(typ)
}

// selectedKernelcachePath returns the kernelcache for the device-filtered
// identities: the first KernelCache path in manifest order. A product type may
// span several boards that share one kernelcache (iPhone8,1 is n71ap and
// n71map), and a board may list several variants (release and research); both
// resolve to the first path, matching the unfiltered path in extractKernelcaches.
func selectedKernelcachePath(inf *info.Info) (string, error) {
	for _, bi := range inf.Plists.BuildIdentities {
		component, ok := bi.Manifest["KernelCache"]
		if !ok {
			continue
		}
		if path, ok := component.Info["Path"].(string); ok && path != "" {
			return path, nil
		}
	}
	return "", fmt.Errorf("selected device has no kernelcache")
}

func extractSelectedKernelcache(inf *info.Info, ipsw, folder string) (string, error) {
	path, err := selectedKernelcachePath(inf)
	if err != nil {
		return "", err
	}
	out, err := kernelcache.ExtractWithInfo(inf, ipsw, folder, path)
	if err != nil {
		return "", err
	}
	if len(out) != 1 {
		return "", fmt.Errorf("expected one extracted kernelcache, got %d", len(out))
	}
	return maps.Keys(out)[0], nil
}
