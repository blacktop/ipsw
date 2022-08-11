package apps

import (
	"archive/zip"
	"io"
	"os"
	"path/filepath"
	"regexp"

	"github.com/blacktop/go-plist"
)

var infoPlistName = regexp.MustCompile("Payload/[a-zA-Z0-9]+.app/Info.plist")

func AppBundleFromIPA(ipa string) (*AppBundle, error) {
	ipaFile, err := zip.OpenReader(ipa)
	if err != nil {
		return nil, err
	}
	defer ipaFile.Close()
	var infoPlistFile *zip.File
	for _, f := range ipaFile.File {
		if infoPlistName.MatchString(f.Name) {
			infoPlistFile = f
			break
		}
	}
	r, err := infoPlistFile.Open()
	if err != nil {
		return nil, err
	}
	defer r.Close()
	data, err := io.ReadAll(r)
	if err != nil {
		return nil, err
	}
	bundle := &AppBundle{}
	if _, err := plist.Unmarshal(data, bundle); err != nil {
		return nil, err
	}
	return bundle, err
}

func AppBundleFromAppBundle(appBundle string) (*AppBundle, error) {
	f, err := os.Open(filepath.Join(appBundle, "Info.plist"))
	if err != nil {
		return nil, err
	}
	defer f.Close()
	bundle := &AppBundle{}
	if err := plist.NewDecoder(f).Decode(bundle); err != nil {
		return nil, err
	}
	return bundle, err
}
