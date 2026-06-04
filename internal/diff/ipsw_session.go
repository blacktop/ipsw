package diff

import (
	"github.com/blacktop/ipsw/pkg/info"
)

// ipswVolumeOrderMachos is the volume order the *InIPSW walkers enumerate:
// FileSystem, SystemOS, AppOS, ExclaveOS. machos/files/plists/localizations
// share it.
var ipswVolumeOrderMachos = []string{"fs", "sys", "app", "exc"}

type ipswVolumeFileSession interface {
	Root(string) (string, error)
	Release(string) error
}

// volumeResolves reports whether the IPSW has the given OS volume, matching the
// exact GetXOsDmg-guarded skips in ForEachMachoInIPSW (skip on ANY getter error;
// no sys->fs fallback, unlike mount.Session.Root("sys")).
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
