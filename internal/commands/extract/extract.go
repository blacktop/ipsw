// Package extract contains the extract commands.
package extract

import (
	"archive/zip"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"slices"
	"strings"

	"github.com/blacktop/go-macho"
	"github.com/blacktop/go-plist"
	fwcmd "github.com/blacktop/ipsw/internal/commands/fw"
	"github.com/blacktop/ipsw/internal/download"
	"github.com/blacktop/ipsw/internal/utils"
	"github.com/blacktop/ipsw/pkg/aea"
	"github.com/blacktop/ipsw/pkg/dyld"
	"github.com/blacktop/ipsw/pkg/img4"
	"github.com/blacktop/ipsw/pkg/info"
	"github.com/blacktop/ipsw/pkg/kernelcache"
	"github.com/blacktop/ipsw/pkg/lzfse"
	"github.com/blacktop/ipsw/pkg/ota"
)

// Config is the extract command configuration.
type Config struct {
	// path to the IPSW
	IPSW string `json:"ipsw,omitempty"`
	// url to the remote IPSW
	URL string `json:"url,omitempty"`
	// regex pattern to search for in the IPSW
	Pattern string `json:"pattern,omitempty"`
	// arches of the DSCs to extract
	Arches []string `json:"arches,omitempty"`
	// extract the DriverKit DSCs
	DriverKit bool `json:"driver_kit,omitempty"`
	// extract a single device's kernelcache
	KernelDevice string `json:"kernel_device,omitempty"`
	// http proxy to use
	Proxy string `json:"proxy,omitempty"`
	// don't verify the certificate chain
	Insecure bool `json:"insecure,omitempty"`
	// search the DMGs for files
	DMGs bool `json:"dmgs,omitempty"`
	// type of DMG to extract
	// pattern: (app|sys|fs)
	DmgType string `json:"dmg_type,omitempty"`
	// flatten the extracted files paths (remove the folders)
	Flatten bool `json:"flatten,omitempty"`
	// show the progress bar (when using the CLI)
	Progress bool `json:"progress,omitempty"`
	// output directory to write extracted files to
	Output string `json:"output,omitempty"`
	// output as JSON
	JSON bool `json:"json,omitempty"`

	info *info.Info
}

func isURL(str string) bool {
	u, err := url.Parse(str)
	return err == nil && u.Scheme != "" && u.Host != ""
}

func getFolder(c *Config) (*info.Info, string, error) {
	if c.info == nil {
		var err error
		c.info, err = info.Parse(filepath.Clean(c.IPSW))
		if err != nil {
			return nil, "", fmt.Errorf("failed to parse plists in IPSW: %v", err)
		}
	}
	folder, err := c.info.GetFolder(c.KernelDevice)
	if err != nil {
		return c.info, folder, fmt.Errorf("failed to get folder from IPSW metadata: %v", err)
	}
	return c.info, folder, nil
}

func getRemoteFolder(c *Config) (*info.Info, *zip.Reader, string, error) {
	zr, err := download.NewRemoteZipReader(c.URL, &download.RemoteConfig{
		Proxy:    c.Proxy,
		Insecure: c.Insecure,
	})
	if err != nil {
		return nil, nil, "", fmt.Errorf("unable to download remote zip: %v", err)
	}
	if c.info == nil {
		c.info, err = info.ParseZipFiles(zr.File)
		if err != nil {
			return nil, nil, "", fmt.Errorf("failed to parse plists in remote zip: %v", err)
		}
	}
	folder, err := c.info.GetFolder(c.KernelDevice)
	if err != nil {
		return nil, nil, "", fmt.Errorf("failed to get folder from remote zip metadata: %v", err)
	}
	return c.info, zr, folder, nil
}

// FirmwareType returns the type of the firmware: IPSW or OTA
func FirmwareType(c *Config) (string, error) {
	var err error
	if len(c.IPSW) > 0 {
		c.info, err = info.Parse(filepath.Clean(c.IPSW))
		if err != nil {
			return "", fmt.Errorf("failed to parse plists in IPSW: %v", err)
		}
		return c.info.Plists.Type, nil
	} else if len(c.URL) > 0 {
		if !isURL(c.URL) {
			return "", fmt.Errorf("invalid URL provided: %s", c.URL)
		}
		c.info, _, _, err = getRemoteFolder(c)
		if err != nil {
			return "", err
		}
		return c.info.Plists.Type, nil
	}
	return "", fmt.Errorf("no IPSW or URL provided")
}

// Kernelcache extracts the kernelcache from an IPSW
func Kernelcache(c *Config) (map[string][]string, error) {
	if len(c.IPSW) > 0 {
		_, folder, err := getFolder(c)
		if err != nil {
			return nil, err
		}
		return kernelcache.Extract(c.IPSW, filepath.Join(filepath.Clean(c.Output), folder), c.KernelDevice)
	} else if len(c.URL) > 0 {
		if !isURL(c.URL) {
			return nil, fmt.Errorf("invalid URL provided: %s", c.URL)
		}
		_, zr, folder, err := getRemoteFolder(c)
		if err != nil {
			return nil, err
		}
		return kernelcache.RemoteParse(zr, filepath.Join(filepath.Clean(c.Output), folder), c.KernelDevice)
	}
	return nil, fmt.Errorf("no IPSW or URL provided")
}

// SPTM extracts the SPTM firmware from an IPSW
func SPTM(c *Config) ([]string, error) {
	var tmpOut []string
	var outfiles []string

	origOutput := c.Output

	tmpDIR, err := os.MkdirTemp("", "ipsw_extract_sptm")
	if err != nil {
		return nil, fmt.Errorf("failed to create temporary directory to store SPTM im4p: %v", err)
	}
	defer os.RemoveAll(tmpDIR)
	c.Output = tmpDIR

	c.Pattern = `.*sptm.*im4p$`
	out, err := Search(c)
	if err != nil {
		return nil, err
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("no SPTM firmware found")
	}

	tmpOut = append(tmpOut, out...)

	c.Pattern = `.*txm.*im4p$`
	out, err = Search(c)
	if err != nil {
		return nil, err
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("no TXM firmware found")
	}

	tmpOut = append(tmpOut, out...)

	c.Output = origOutput

	for _, f := range tmpOut {
		dat, err := os.ReadFile(f)
		if err != nil {
			return nil, fmt.Errorf("failed to open '%s': %v", f, err)
		}

		im4p, err := img4.ParseIm4p(bytes.NewReader(dat))
		if err != nil {
			return nil, fmt.Errorf("failed to parse '%s': %v", f, err)
		}

		folder := filepath.Join(filepath.Clean(c.Output), strings.TrimPrefix(filepath.Dir(f), tmpDIR))
		fname := filepath.Join(folder, strings.TrimSuffix(filepath.Base(f), ".im4p"))
		if err := os.MkdirAll(folder, 0o750); err != nil {
			return nil, fmt.Errorf("failed to create output directory '%s': %v", folder, err)
		}

		if bytes.Contains(im4p.Data[:4], []byte("bvx2")) {
			dat, err = lzfse.NewDecoder(im4p.Data).DecodeBuffer()
			if err != nil {
				return nil, fmt.Errorf("failed to decompress '%s': %v", f, err)
			}
			if err = os.WriteFile(fname, dat, 0o666); err != nil {
				return nil, fmt.Errorf("failed to write '%s': %v", fname, err)
			}
			outfiles = append(outfiles, fname)
		} else {
			if err = os.WriteFile(fname, im4p.Data, 0o666); err != nil {
				return nil, fmt.Errorf("failed to write '%s': %v", fname, err)
			}
			outfiles = append(outfiles, fname)
		}
	}

	return outfiles, nil
}

func Exclave(c *Config) ([]string, error) {
	var tmpOut []string
	var outfiles []string

	origOutput := c.Output

	tmpDIR, err := os.MkdirTemp("", "ipsw_extract_exclave")
	if err != nil {
		return nil, fmt.Errorf("failed to create temporary directory to store Exlave im4p: %v", err)
	}
	defer os.RemoveAll(tmpDIR)
	c.Output = tmpDIR

	c.Pattern = `.*exclavecore_bundle.*im4p$`
	out, err := Search(c)
	if err != nil {
		return nil, err
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("no Exclave bundles found")
	}

	tmpOut = append(tmpOut, out...)

	c.Output = origOutput

	for _, f := range tmpOut {
		if strings.Contains(f, ".restore.") {
			continue // TODO: skip restore bundles for now
		}
		dat, err := os.ReadFile(f)
		if err != nil {
			return nil, fmt.Errorf("failed to open '%s': %v", f, err)
		}

		im4p, err := img4.ParseIm4p(bytes.NewReader(dat))
		if err != nil {
			return nil, fmt.Errorf("failed to parse '%s': %v", f, err)
		}

		folder := filepath.Join(filepath.Clean(c.Output), strings.TrimPrefix(filepath.Dir(f), tmpDIR))
		fname := filepath.Join(folder, strings.TrimSuffix(filepath.Base(f), ".im4p"))
		if err := os.MkdirAll(folder, 0o750); err != nil {
			return nil, fmt.Errorf("failed to create output directory '%s': %v", folder, err)
		}

		if bytes.Contains(im4p.Data[:4], []byte("bvx2")) {
			dat, err = lzfse.NewDecoder(im4p.Data).DecodeBuffer()
			if err != nil {
				return nil, fmt.Errorf("failed to decompress '%s': %v", f, err)
			}
			if err = os.WriteFile(fname, dat, 0o666); err != nil {
				return nil, fmt.Errorf("failed to write '%s': %v", fname, err)
			}
			outfiles = append(outfiles, fname)
		} else {
			if err = os.WriteFile(fname, im4p.Data, 0o666); err != nil {
				return nil, fmt.Errorf("failed to write '%s': %v", fname, err)
			}
			outfiles = append(outfiles, fname)
		}
	}

	for _, exc := range outfiles {
		out, err := fwcmd.Extract(exc, filepath.Dir(exc))
		if err != nil {
			return nil, fmt.Errorf("failed to extract files from exclave bundle: %v", err)
		}
		outfiles = append(outfiles, out...)
	}

	return outfiles, nil
}

// DSC extracts the DSC file from an IPSW
func DSC(c *Config) ([]string, error) {
	if len(c.IPSW) > 0 {
		_, folder, err := getFolder(c)
		if err != nil {
			return nil, err
		}
		return dyld.Extract(c.IPSW, filepath.Join(filepath.Clean(c.Output), folder), c.Arches, c.DriverKit)
	} else if len(c.URL) > 0 {
		if !isURL(c.URL) {
			return nil, fmt.Errorf("invalid URL provided: %s", c.URL)
		}
		i, zr, folder, err := getRemoteFolder(c)
		if err != nil {
			return nil, err
		}
		if i.Plists.Type == "OTA" {
			if runtime.GOOS == "darwin" {
				out, err := dyld.ExtractFromRemoteCryptex(zr, filepath.Join(filepath.Clean(c.Output), folder), c.Arches, c.DriverKit)
				if err != nil {
					if errors.Is(err, dyld.ErrNoCryptex) {
						c.Pattern = `^` + dyld.CacheRegex
						rfiles, err := ota.RemoteList(zr)
						if err != nil {
							return nil, fmt.Errorf("failed to list files in remote OTA: %v", err)
						}
						var dcaches []string
						for _, f := range rfiles {
							if regexp.MustCompile(c.Pattern).MatchString(f.Name()) {
								dcaches = append(dcaches, f.Name())
							}
						}
						out, err = ota.RemoteExtract(zr, c.Pattern, filepath.Join(filepath.Clean(c.Output), folder), func(s string) bool {
							s = strings.TrimPrefix(s, folder+string(os.PathSeparator))
							if slices.Contains(dcaches, s) {
								dcaches = utils.RemoveStrFromSlice(dcaches, s)
								if len(dcaches) == 0 {
									return true
								}
							}
							return false
						})
						if err != nil {
							return nil, fmt.Errorf("failed to extract OTA: %v", err)
						}
					} else {
						return nil, fmt.Errorf("failed to extract dyld_shared_cache from remote OTA: %v", err)
					}
				}
				return out, nil
			}
			return nil, fmt.Errorf("extracting dyld_shared_cache from remote OTA is only supported on macOS")
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
		return dyld.ExtractFromDMG(i, filepath.Join(tmpDIR, sysDMG), filepath.Join(filepath.Clean(c.Output), folder), c.Arches, c.DriverKit)
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
			return nil, fmt.Errorf("failed to find appOS DMG in IPSW: %v", err)
		}
	case "sys":
		dmgPath, err = i.GetSystemOsDmg()
		if err != nil {
			return nil, fmt.Errorf("failed to find systemOS DMG in IPSW: %v", err)
		}
	case "fs":
		dmgPath, err = i.GetFileSystemOsDmg()
		if err != nil {
			return nil, fmt.Errorf("failed to find filesystem DMG in IPSW: %v", err)
		}
	case "exc":
		dmgPath, err = i.GetExclaveOSDmg()
		if err != nil {
			return nil, fmt.Errorf("failed to find exclaveOS DMG in IPSW: %v", err)
		}
	}

	return utils.SearchZip(zr.File, regexp.MustCompile(dmgPath), filepath.Join(filepath.Clean(c.Output), folder), c.Flatten, c.Progress)
}

// Keybags extracts the keybags from an IPSW
func Keybags(c *Config) (fname string, err error) {
	if len(c.IPSW) == 0 && len(c.URL) == 0 {
		return "", fmt.Errorf("no IPSW or URL provided")
	}

	var i *info.Info
	var folder string
	var kbags *img4.KeyBags

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
		kbags, err = img4.ParseZipKeyBags(zr.File, i, c.Pattern)
		if err != nil {
			return "", fmt.Errorf("failed to parse im4p kbags: %v", err)
		}
	} else if len(c.URL) > 0 {
		var zr *zip.Reader
		if !isURL(c.URL) {
			return "", fmt.Errorf("invalid URL provided: %s", c.URL)
		}
		i, zr, folder, err = getRemoteFolder(c)
		if err != nil {
			return "", err
		}
		kbags, err = img4.ParseZipKeyBags(zr.File, i, c.Pattern)
		if err != nil {
			return "", fmt.Errorf("failed to parse im4p kbags: %v", err)
		}
	}

	out, err := json.Marshal(kbags)
	if err != nil {
		return "", fmt.Errorf("failed to marshal im4p kbags: %v", err)
	}

	if c.JSON {
		return string(out), nil
	}

	fname = filepath.Join(filepath.Join(filepath.Clean(c.Output), folder), "kbags.json")
	if err := os.MkdirAll(filepath.Dir(fname), 0o750); err != nil {
		return "", fmt.Errorf("failed to create directory %s: %v", filepath.Dir(fname), err)
	}
	if err := os.WriteFile(fname, out, 0o666); err != nil {
		return "", fmt.Errorf("failed to write %s: %v", filepath.Join(filepath.Join(filepath.Clean(c.Output), folder), "kbags.json"), err)
	}

	return
}

// FcsKeys extracts the AEA1 DMG fsc-keys from an IPSW
func FcsKeys(c *Config) ([]string, error) {
	if len(c.IPSW) == 0 && len(c.URL) == 0 {
		return nil, fmt.Errorf("no IPSW or URL provided")
	}

	var artifacts []string

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

	var dmgPaths []string
	dmgPath, err := i.GetSystemOsDmg()
	if err != nil {
		return nil, fmt.Errorf("failed to find systemOS DMG in IPSW: %v", err)
	}
	dmgPaths = append(dmgPaths, dmgPath)
	dmgPath, err = i.GetFileSystemOsDmg()
	if err != nil {
		return nil, fmt.Errorf("failed to find filesystem DMG in IPSW: %v", err)
	}
	dmgPaths = append(dmgPaths, dmgPath)

	kmap := make(map[string]aea.PrivateKey)

	for _, dmgPath := range dmgPaths {
		if filepath.Ext(dmgPath) != ".aea" {
			return nil, fmt.Errorf("fcs-keys are only found in AEA1 DMGs: found '%s'", filepath.Base(dmgPath))
		}

		out, err := utils.SearchPartialZip(zr.File, regexp.MustCompile(dmgPath+`$`), os.TempDir(), 0x1000, false, false)
		if err != nil {
			return nil, fmt.Errorf("failed to extract fcs-keys from DMG: %v", err)
		}
		defer func() {
			for _, f := range out {
				os.Remove(f)
			}
		}()

		for _, f := range out {
			metadata, err := aea.Info(filepath.Clean(f))
			if err != nil {
				return nil, fmt.Errorf("failed to parse AEA1 metadata: %v", err)
			}
			pkmap, err := metadata.GetPrivateKey(nil, true)
			if err != nil {
				return nil, err
			}

			if c.JSON {
				// check if json file exists
				if _, err := os.Stat(filepath.Join(filepath.Clean(c.Output), "fcs-keys.json")); !os.IsNotExist(err) {
					data, err := os.ReadFile(filepath.Join(filepath.Clean(c.Output), "fcs-keys.json"))
					if err != nil {
						return nil, fmt.Errorf("failed to read fcs-keys.json: %v", err)
					}
					if err := json.Unmarshal(data, &kmap); err != nil {
						return nil, fmt.Errorf("failed to unmarshal fcs-keys: %v", err)
					}
				}
				maps.Copy(kmap, pkmap)
			} else {
				for _, pk := range pkmap {
					fname := filepath.Join(filepath.Clean(c.Output), folder, filepath.Base(dmgPath)+".pem")

					if err := os.MkdirAll(filepath.Dir(fname), 0o750); err != nil {
						return nil, fmt.Errorf("failed to create directory %s: %v", filepath.Dir(fname), err)
					}

					if err := os.WriteFile(fname, pk, 0o644); err != nil {
						return nil, fmt.Errorf("failed to write fcs-key.pem: %v", err)
					}

					artifacts = append(artifacts, fname)
				}
			}
		}
	}

	if c.JSON {
		out, err := json.Marshal(kmap)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal fcs-keys: %v", err)
		}
		fname := filepath.Join(filepath.Clean(c.Output), "fcs-keys.json")
		if err := os.WriteFile(fname, out, 0o644); err != nil {
			return nil, fmt.Errorf("failed to write fcs-keys.json: %v", err)
		}
		artifacts = append(artifacts, fname)
	}

	return artifacts, nil
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
		if err != nil && !c.DMGs {
			return nil, fmt.Errorf("failed to extract files matching pattern from ZIP: %v", err)
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
			if excOS, err := i.GetExclaveOSDmg(); err == nil {
				out, err := utils.ExtractFromDMG(c.IPSW, excOS, destPath, re)
				if err != nil {
					return nil, fmt.Errorf("failed to extract files from ExclaveOS %s: %v", excOS, err)
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

// LaunchdConfig extracts launchd config from an IPSW
func LaunchdConfig(path string) (string, error) {
	ipswPath := filepath.Clean(path)

	i, err := info.Parse(ipswPath)
	if err != nil {
		return "", fmt.Errorf("failed to parse IPSW: %v", err)
	}
	fsDMG, err := i.GetFileSystemOsDmg()
	if err != nil {
		return "", fmt.Errorf("failed to get filesystem DMG path: %v", err)
	}
	extracted, err := utils.ExtractFromDMG(ipswPath, fsDMG, os.TempDir(), regexp.MustCompile(`.*/sbin/launchd$`))
	if err != nil {
		return "", fmt.Errorf("failed to extract launchd from %s: %v", fsDMG, err)
	}

	if len(extracted) == 0 {
		return "", fmt.Errorf("failed to extract launchd from %s: no files extracted", fsDMG)
	} else if len(extracted) > 1 {
		return "", fmt.Errorf("failed to extract launchd from %s: too many files extracted", fsDMG)
	}
	defer os.Remove(filepath.Clean(extracted[0]))

	var m *macho.File
	fat, err := macho.OpenFat(filepath.Clean(extracted[0]))
	if err == nil {
		m = fat.Arches[len(fat.Arches)-1].File // grab last arch (probably arm64e)
	} else {
		if err == macho.ErrNotFat {
			m, err = macho.Open(filepath.Clean(extracted[0]))
			if err != nil {
				return "", fmt.Errorf("failed to open macho file: %v", err)
			}
		} else {
			return "", fmt.Errorf("failed to open universal macho file: %v", err)
		}
	}

	data, err := m.Section("__TEXT", "__config").Data()
	if err != nil {
		return "", fmt.Errorf("failed to get launchd config: %v", err)
	}

	return string(data), nil
}

// SystemVersionPlist is the SystemVersion.plist struct
type SystemVersionPlist struct {
	BuildID             string `json:"build_id,omitempty"`
	ProductBuildVersion string `json:"product_build_version,omitempty"`
	ProductCopyright    string `json:"product_copyright,omitempty"`
	ProductName         string `json:"product_name,omitempty"`
	ProductVersion      string `json:"product_version,omitempty"`
	ReleaseType         string `json:"release_type,omitempty"`
	SystemImageID       string `json:"system_image_id,omitempty"`
}

// SystemVersion extracts the system version info from an IPSW
func SystemVersion(path string) (*SystemVersionPlist, error) {
	ipswPath := filepath.Clean(path)

	i, err := info.Parse(ipswPath)
	if err != nil {
		return nil, fmt.Errorf("failed to parse IPSW: %v", err)
	}
	fsDMG, err := i.GetFileSystemOsDmg()
	if err != nil {
		return nil, fmt.Errorf("failed to get filesystem DMG path: %v", err)
	}

	extracted, err := utils.ExtractFromDMG(ipswPath, fsDMG, os.TempDir(), regexp.MustCompile(`System/Library/CoreServices/SystemVersion.plist$`))
	if err != nil {
		return nil, fmt.Errorf("failed to extract launchd from %s: %v", fsDMG, err)
	}

	if len(extracted) == 0 {
		return nil, fmt.Errorf("failed to extract SystemVersion.plist from %s: no files extracted", fsDMG)
	} else if len(extracted) > 1 {
		return nil, fmt.Errorf("failed to extract SystemVersion.plist from %s: too many files extracted", fsDMG)
	}
	defer os.Remove(filepath.Clean(extracted[0]))

	dat, err := os.ReadFile(extracted[0])
	if err != nil {
		return nil, fmt.Errorf("failed to read SystemVersion.plist: %v", err)
	}

	var sysVer SystemVersionPlist
	if err := plist.NewDecoder(bytes.NewReader(dat)).Decode(&sysVer); err != nil {
		return nil, fmt.Errorf("failed to decode SystemVersion.plist: %v", err)
	}

	return &sysVer, nil
}
