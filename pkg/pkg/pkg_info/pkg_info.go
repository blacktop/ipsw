package pkg_info

import (
	"encoding/xml"
	"io"
	"os"
	"sort"
)

type Bundle struct {
	ID            string `xml:"id,attr"`
	Path          string `xml:"path,attr"`
	Version       string `xml:"CFBundleVersion,attr,omitempty"`
	ShortVersion  string `xml:"CFBundleShortVersionString,attr,omitempty"`
	SourceVersion string `xml:"SourceVersion,attr,omitempty"`
}

type BundleVersion struct {
	Bundles []Bundle `xml:"bundle"`
}

type PackageInfo struct {
	XMLName         xml.Name      `xml:"pkg-info"`
	FormatVersion   string        `xml:"format-version,attr"`
	Relocatable     string        `xml:"relocatable,attr"`
	Overwrite       string        `xml:"overwrite-permissions,attr"`
	UseHFSPlus      string        `xml:"useHFSPlusCompression,attr"`
	Auth            string        `xml:"auth,attr"`
	Identifier      string        `xml:"identifier,attr"`
	InstallLocation string        `xml:"install-location,attr"`
	Version         string        `xml:"version,attr"`
	BundleVersion   BundleVersion `xml:"bundle-version"`
}

func (p *PackageInfo) Files() []string {
	var files []string
	for _, bundle := range p.BundleVersion.Bundles {
		files = append(files, bundle.Path)
	}
	sort.StringSlice(files).Sort()
	return files
}

func parse(data []byte) (*PackageInfo, error) {
	var pkgInfo PackageInfo
	if err := xml.Unmarshal(data, &pkgInfo); err != nil {
		return nil, err
	}
	return &pkgInfo, nil
}

func Open(path string) (*PackageInfo, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return parse(data)
}

func Read(r io.ReadCloser) (*PackageInfo, error) {
	data, err := io.ReadAll(r)
	if err != nil {
		return nil, err
	}
	return parse(data)
}
