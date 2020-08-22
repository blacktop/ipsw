package kernelcache

import (
	"bytes"
	"fmt"
	"os"

	"github.com/blacktop/go-macho"
	"github.com/blacktop/go-plist"
)

type PrelinkInfo struct {
	PrelinkInfoDictionary []CFBundle `plist:"_PrelinkInfoDictionary,omitempty"`
}

type CFBundle struct {
	Name                  string `plist:"CFBundleName,omitempty"`
	ID                    string `plist:"CFBundleIdentifier,omitempty"`
	InfoDictionaryVersion string `plist:"CFBundleInfoDictionaryVersion,omitempty"`
	CompatibleVersion     string `plist:"OSBundleCompatibleVersion,omitempty"`
	Version               string `plist:"CFBundleVersion,omitempty"`
	Required              string `plist:"OSBundleRequired,omitempty"`
	Executable            string `plist:"CFBundleExecutable,omitempty"`
	OSKernelResource      bool   `plist:"OSKernelResource,omitempty"`
	GetInfoString         string `plist:"CFBundleGetInfoString,omitempty"`
	AllowUserLoad         bool   `plist:"OSBundleAllowUserLoad,omitempty"`
	Signature             string `plist:"CFBundleSignature,omitempty"`
	PackageType           string `plist:"CFBundlePackageType,omitempty"`
	DevelopmentRegion     string `plist:"CFBundleDevelopmentRegion,omitempty"`
	ShortVersionString    string `plist:"CFBundleShortVersionString,omitempty"`
	ExecutableLoadAddr    uint64 `plist:"_PrelinkExecutableLoadAddr,omitempty"`
}

// KextList lists all the kernel extensions in the kernelcache
func KextList(kernel string) error {
	m, err := macho.Open(kernel)
	if err != nil {
		return err
	}
	defer m.Close()

	for _, sec := range m.Sections {
		if sec.Seg == "__PRELINK_INFO" && sec.Name == "__info" {
			f, err := os.Open(kernel)
			if err != nil {
				return err
			}

			data := make([]byte, sec.Size)
			f.Seek(int64(sec.Offset), os.SEEK_SET)
			_, err = f.Read(data)
			if err != nil {
				return err
			}

			var prelink PrelinkInfo
			decoder := plist.NewDecoder(bytes.NewReader(bytes.Trim([]byte(data), "\x00")))
			err = decoder.Decode(&prelink)
			if err != nil {
				return err
			}

			fmt.Println("FOUND:", len(prelink.PrelinkInfoDictionary))
			for _, bundle := range prelink.PrelinkInfoDictionary {
				fmt.Printf("%s (%s)\n", bundle.ID, bundle.Version)
			}
			break
		}
	}
	return nil
}
