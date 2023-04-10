// Package extract contains the extract commands.
package extract

import (
	"archive/zip"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"regexp"

	"github.com/apex/log"
	"github.com/blacktop/ipsw/internal/download"
	"github.com/blacktop/ipsw/internal/utils"
	"github.com/blacktop/ipsw/pkg/dyld"
	"github.com/blacktop/ipsw/pkg/img4"
	"github.com/blacktop/ipsw/pkg/info"
	"github.com/blacktop/ipsw/pkg/kernelcache"
)

// Config is the extract command configuration.
type Config struct {
	IPSW     string   `json:"ipsw,omitempty"`
	URL      string   `json:"url,omitempty"`
	Pattern  string   `json:"pattern,omitempty"`
	Arches   []string `json:"arches,omitempty"`
	Proxy    string   `json:"proxy,omitempty"`
	Insecure bool     `json:"insecure,omitempty"`
	DMGs     bool     `json:"dmgs,omitempty"`
	DmgType  string   `json:"dmg_type,omitempty"`
	Flatten  bool     `json:"flatten,omitempty"`
	Progress bool     `json:"progress,omitempty"`
	Output   string   `json:"output,omitempty"`
}

func isURL(str string) bool {
	u, err := url.Parse(str)
	return err == nil && u.Scheme != "" && u.Host != ""
}

func getFolder(c *Config) (*info.Info, string, error) {
	c.IPSW = filepath.Clean(c.IPSW)
	i, err := info.Parse(c.IPSW)
	if err != nil {
		return nil, "", fmt.Errorf("failed to parse plists in IPSW: %v", err)
	}
	folder, err := i.GetFolder()
	if err != nil {
		log.Errorf("failed to get folder from IPSW metadata: %v", err)
	}
	return i, folder, nil
}

func getRemoteFolder(c *Config) (*info.Info, *zip.Reader, string, error) {
	zr, err := download.NewRemoteZipReader(c.URL, &download.RemoteConfig{
		Proxy:    c.Proxy,
		Insecure: c.Insecure,
	})
	if err != nil {
		return nil, nil, "", fmt.Errorf("unable to download remote zip: %v", err)
	}
	i, err := info.ParseZipFiles(zr.File)
	if err != nil {
		return nil, nil, "", fmt.Errorf("failed to parse plists in remote zip: %v", err)
	}
	folder, err := i.GetFolder()
	if err != nil {
		return nil, nil, "", fmt.Errorf("failed to get folder from remote zip metadata: %v", err)
	}
	return i, zr, folder, nil
}

// Kernelcache extracts the kernelcache from an IPSW
func Kernelcache(c *Config) ([]string, error) {
	if len(c.IPSW) > 0 {
		_, folder, err := getFolder(c)
		if err != nil {
			return nil, err
		}
		return kernelcache.Extract(c.IPSW, filepath.Join(filepath.Clean(c.Output), folder))
	} else if len(c.URL) > 0 {
		if !isURL(c.URL) {
			return nil, fmt.Errorf("invalid URL provided: %s", c.URL)
		}
		_, zr, folder, err := getRemoteFolder(c)
		if err != nil {
			return nil, err
		}
		return kernelcache.RemoteParse(zr, filepath.Join(filepath.Clean(c.Output), folder))
	}
	return nil, fmt.Errorf("no IPSW or URL provided")
}

// DSC extracts the DSC file from an IPSW
func DSC(c *Config) ([]string, error) {
	if len(c.IPSW) > 0 {
		_, folder, err := getFolder(c)
		if err != nil {
			return nil, err
		}
		return dyld.Extract(c.IPSW, filepath.Join(filepath.Clean(c.Output), folder), c.Arches)
	} else if len(c.URL) > 0 {
		if !isURL(c.URL) {
			return nil, fmt.Errorf("invalid URL provided: %s", c.URL)
		}
		i, zr, folder, err := getRemoteFolder(c)
		if err != nil {
			return nil, err
		}
		sysDMG, err := i.GetSystemOsDmg()
		if err != nil {
			return nil, fmt.Errorf("only iOS16.x/macOS13.x supported: failed to get SystemOS DMG from remote zip metadata: %v", err)
		}
		if len(sysDMG) == 0 {
			return nil, fmt.Errorf("only iOS16.x/macOS13.x supported: no SystemOS DMG found in remote zip metadata")
		}
		tmpDIR, err := os.MkdirTemp("", "ipsw_extract_remote_dyld")
		if err != nil {
			return nil, fmt.Errorf("failed to create temporary directory to store SystemOS DMG: %v", err)
		}
		defer os.RemoveAll(tmpDIR)
		if _, err := utils.SearchZip(zr.File, regexp.MustCompile(fmt.Sprintf("^%s$", sysDMG)), tmpDIR, c.Flatten, true); err != nil {
			return nil, fmt.Errorf("failed to extract SystemOS DMG from remote IPSW: %v", err)
		}
		return dyld.ExtractFromDMG(i, filepath.Join(tmpDIR, sysDMG), filepath.Join(filepath.Clean(c.Output), folder), c.Arches)
	}
	return nil, fmt.Errorf("no IPSW or URL provided")
}

// DMG extracts the DMG from an IPSW
func DMG(c *Config) ([]string, error) {
	if len(c.IPSW) == 0 && len(c.URL) == 0 {
		return nil, fmt.Errorf("no IPSW or URL provided")
	}

	var err error
	var i *info.Info
	var folder string
	var zr *zip.Reader

	if len(c.IPSW) > 0 {
		i, folder, err = getFolder(c)
		if err != nil {
			return nil, err
		}
		f, err := os.Open(filepath.Clean(c.IPSW))
		if err != nil {
			return nil, fmt.Errorf("failed to open IPSW: %v", err)
		}
		defer f.Close()
		finfo, err := f.Stat()
		if err != nil {
			return nil, fmt.Errorf("failed to stat IPSW: %v", err)
		}
		zr, err = zip.NewReader(f, finfo.Size())
		if err != nil {
			return nil, fmt.Errorf("failed to open IPSW: %v", err)
		}
	} else if len(c.URL) > 0 {
		if !isURL(c.URL) {
			return nil, fmt.Errorf("invalid URL provided: %s", c.URL)
		}
		i, zr, folder, err = getRemoteFolder(c)
		if err != nil {
			return nil, err
		}
	}

	var dmgPath string
	switch c.DmgType {
	case "app":
		dmgPath, err = i.GetAppOsDmg()
		if err != nil {
			return nil, fmt.Errorf("failed to find app DMG in IPSW: %v", err)
		}
	case "sys":
		dmgPath, err = i.GetSystemOsDmg()
		if err != nil {
			return nil, fmt.Errorf("failed to find system DMG in IPSW: %v", err)
		}
	case "fs":
		dmgPath, err = i.GetFileSystemOsDmg()
		if err != nil {
			return nil, fmt.Errorf("failed to find filesystem DMG in IPSW: %v", err)
		}
	}

	return utils.SearchZip(zr.File, regexp.MustCompile(dmgPath), filepath.Join(filepath.Clean(c.Output), folder), c.Flatten, c.Progress)
}

// Keybags extracts the keybags from an IPSW
func Keybags(c *Config) (string, error) {
	if len(c.IPSW) == 0 && len(c.URL) == 0 {
		return "", fmt.Errorf("no IPSW or URL provided")
	}

	var err error
	var i *info.Info
	var folder string
	var zr *zip.Reader

	if len(c.IPSW) > 0 {
		i, folder, err = getFolder(c)
		if err != nil {
			return "", err
		}
		zr, err := zip.OpenReader(filepath.Clean(c.IPSW))
		if err != nil {
			return "", fmt.Errorf("failed to open IPSW: %v", err)
		}
		defer zr.Close()
	} else if len(c.URL) > 0 {
		if !isURL(c.URL) {
			return "", fmt.Errorf("invalid URL provided: %s", c.URL)
		}
		i, zr, folder, err = getRemoteFolder(c)
		if err != nil {
			return "", err
		}
	}

	kbags, err := img4.ParseZipKeyBags(zr.File, i, c.Pattern)
	if err != nil {
		return "", fmt.Errorf("failed to parse im4p kbags: %v", err)
	}

	out, err := json.Marshal(kbags)
	if err != nil {
		return "", fmt.Errorf("failed to marshal im4p kbags: %v", err)
	}

	fname := filepath.Join(filepath.Join(filepath.Clean(c.Output), folder), "kbags.json")
	if err := os.MkdirAll(filepath.Dir(fname), 0750); err != nil {
		return "", fmt.Errorf("failed to create directory %s: %v", filepath.Dir(fname), err)
	}
	if err := os.WriteFile(fname, out, 0660); err != nil {
		return "", fmt.Errorf("failed to write %s: %v", filepath.Join(filepath.Join(filepath.Clean(c.Output), folder), "kbags.json"), err)
	}

	return fname, nil
}

// Search searches for files matching a pattern in an IPSW
func Search(c *Config) ([]string, error) {
	var artifacts []string

	if len(c.Pattern) == 0 {
		return nil, fmt.Errorf("no pattern provided")
	}
	re, err := regexp.Compile(c.Pattern)
	if err != nil {
		return nil, fmt.Errorf("failed to compile regexp '%s': %v", c.Pattern, err)
	}
	if len(c.IPSW) > 0 {
		i, folder, err := getFolder(c)
		if err != nil {
			return nil, err
		}
		destPath := filepath.Join(filepath.Clean(c.Output), folder)
		zr, err := zip.OpenReader(c.IPSW)
		if err != nil {
			return nil, fmt.Errorf("failed to open IPSW: %v", err)
		}
		defer zr.Close()
		out, err := utils.SearchZip(zr.File, re, destPath, c.Flatten, false)
		if err != nil {
			return nil, fmt.Errorf("failed to extract files matching pattern: %v", err)
		}
		artifacts = append(artifacts, out...)
		if c.DMGs { // SEARCH THE DMGs
			if appOS, err := i.GetAppOsDmg(); err == nil {
				out, err := utils.ExtractFromDMG(c.IPSW, appOS, destPath, re)
				if err != nil {
					return nil, fmt.Errorf("failed to extract files from AppOS %s: %v", appOS, err)
				}
				artifacts = append(artifacts, out...)
			}
			if systemOS, err := i.GetSystemOsDmg(); err == nil {
				out, err := utils.ExtractFromDMG(c.IPSW, systemOS, destPath, re)
				if err != nil {
					return nil, fmt.Errorf("failed to extract files from SystemOS %s: %v", systemOS, err)
				}
				artifacts = append(artifacts, out...)
			}
			if fsOS, err := i.GetFileSystemOsDmg(); err == nil {
				out, err := utils.ExtractFromDMG(c.IPSW, fsOS, destPath, re)
				if err != nil {
					return nil, fmt.Errorf("failed to extract files from filesystem %s: %v", fsOS, err)
				}
				artifacts = append(artifacts, out...)
			}
		}
		return artifacts, nil
	} else if len(c.URL) > 0 {
		if !isURL(c.URL) {
			return nil, fmt.Errorf("invalid URL provided: %s", c.URL)
		}
		if c.DMGs { // SEARCH THE DMGs
			return nil, fmt.Errorf("searching DMGs in remote IPSW is not supported")
		}
		_, zr, folder, err := getRemoteFolder(c)
		if err != nil {
			return nil, err
		}
		artifacts, err = utils.SearchZip(zr.File, re, filepath.Join(filepath.Clean(c.Output), folder), c.Flatten, true)
		if err != nil {
			return nil, fmt.Errorf("failed to extract files matching pattern '%s' in remote IPSW: %v", c.Pattern, err)
		}
		return artifacts, nil
	}
	return nil, fmt.Errorf("no IPSW or URL provided")
}
