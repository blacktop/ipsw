package distrib

import (
	"encoding/xml"
	"io"
	"os"
)

// Distribution represents the top-level installer GUI script
type Distribution struct {
	XMLName        xml.Name       `xml:"installer-gui-script"`
	MinSpecVersion string         `xml:"minSpecVersion,attr"`
	Options        Options        `xml:"options"`
	Title          string         `xml:"title"`
	VolumeCheck    ScriptCheck    `xml:"volume-check"`
	InstallCheck   ScriptCheck    `xml:"installation-check"`
	License        File           `xml:"license"`
	Readme         File           `xml:"readme"`
	ChoicesOutline ChoicesOutline `xml:"choices-outline"`
	Choices        []Choice       `xml:"choice"`
	Scripts        []string       `xml:"script"`
	PackageRefs    []PackageRef   `xml:"pkg-ref"`
}

type Options struct {
	HostArchitectures string `xml:"hostArchitectures,attr"`
	Customize         string `xml:"customize,attr"`
}

type ScriptCheck struct {
	Script string `xml:"script,attr"`
}

type File struct {
	Path string `xml:"file,attr"`
}

type ChoicesOutline struct {
	Lines []Line `xml:"line"`
}

type Line struct {
	Choice string `xml:"choice,attr"`
}

type Choice struct {
	ID     string   `xml:"id,attr"`
	Title  string   `xml:"title,attr"`
	PkgRef []PkgRef `xml:"pkg-ref"`
}

type PkgRef struct {
	ID                string `xml:"id,attr"`
	Auth              string `xml:"auth,attr"`
	PackageIdentifier string `xml:"packageIdentifier,attr"`
	Value             string `xml:",chardata"`
}

type PackageRef struct {
	ID            string `xml:"id,attr"`
	InstallKBytes string `xml:"installKBytes,attr"`
	Version       string `xml:"version,attr"`
}

func (p *Distribution) GetScripts() map[string][]string {
	scripts := make(map[string][]string)
	if len(p.Scripts) > 0 {
		scripts["main"] = p.Scripts
	}
	if p.VolumeCheck.Script != "" {
		scripts["volume-check"] = append(scripts["volume-check"], p.VolumeCheck.Script)
	}
	if p.InstallCheck.Script != "" {
		scripts["install-check"] = append(scripts["install-check"], p.InstallCheck.Script)
	}
	return scripts
}

func parse(data []byte) (*Distribution, error) {
	var dist Distribution
	if err := xml.Unmarshal(data, &dist); err != nil {
		return nil, err
	}
	return &dist, nil
}

func Open(path string) (*Distribution, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return parse(data)
}

func Read(r io.ReadCloser) (*Distribution, error) {
	data, err := io.ReadAll(r)
	if err != nil {
		return nil, err
	}
	return parse(data)
}
