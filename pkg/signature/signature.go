package signature

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/apex/log"
	"github.com/blacktop/go-macho"
	"github.com/blacktop/go-macho/types"
	"github.com/blacktop/ipsw/internal/utils"
	"github.com/blacktop/ipsw/pkg/disass"
	"github.com/blacktop/ipsw/pkg/kernelcache"
	semver "github.com/hashicorp/go-version"
)

var ErrUnsupportedTarget = errors.New("target not supported")
var ErrUnsupportedVersion = errors.New("version not supported")

func Parse(dir string) (sigs []Symbolicator, err error) {
	if err := filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if !info.IsDir() {
			if filepath.Ext(path) != ".json" {
				return nil
			}
			data, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			var sig Symbolicator
			if err := json.Unmarshal(data, &sig); err != nil {
				return err
			}
			sigs = append(sigs, sig)
		}
		return nil
	}); err != nil {
		return nil, err
	}
	return sigs, nil
}

func CheckVersion(m *macho.File, sigs Symbolicator) (bool, error) {
	kv, err := kernelcache.GetVersion(m)
	if err != nil {
		return false, fmt.Errorf("failed to get kernelcache version: %v", err)
	}
	darwin, err := semver.NewVersion(kv.Darwin)
	if err != nil {
		return false, fmt.Errorf("failed to convert kernel version into semver object: %v", err)
	}
	minVer, err := semver.NewVersion(sigs.Version.Min)
	if err != nil {
		log.Fatal("failed to convert signature min version into semver object")
	}
	maxVer, err := semver.NewVersion(sigs.Version.Max)
	if err != nil {
		log.Fatal("failed to convert signature max version into semver object")
	}
	if darwin.GreaterThanOrEqual(minVer) && darwin.LessThanOrEqual(maxVer) {
		return true, nil
	}
	return false, nil
}

func truncate(in string, length int) string {
	if len(in) > length {
		return in[:length] + "..."
	}
	return in
}

func symbolicate(m *macho.File, name string, sigs Symbolicator, quiet bool) (map[uint64]string, error) {
	symbolMap := make(map[uint64]string)

	text := m.Section("__TEXT_EXEC", "__text")
	if text == nil {
		return nil, fmt.Errorf("failed to find __TEXT_EXEC.__text section")
	}
	data, err := text.Data()
	if err != nil {
		return nil, fmt.Errorf("failed to get data from __TEXT_EXEC.__text section: %v", err)
	}

	engine := disass.NewMachoDisass(m, &symbolMap, &disass.Config{
		Data:         data,
		StartAddress: text.Addr,
	})

	log.WithField("name", name).Info("Analyzing MachO...")
	if err := engine.Triage(); err != nil {
		return nil, fmt.Errorf("first pass triage failed: %v", err)
	}

	cstrs, err := m.GetCStrings()
	if err != nil {
		return nil, err
	}

	for _, sig := range sigs.Signatures {
		found := false
		for _, anchor := range sig.Anchors {
			if addr, ok := cstrs[fmt.Sprintf("%s.%s", anchor.Segment, anchor.Section)][anchor.String]; ok {
				if ok, loc := engine.Contains(addr); ok {
					fn, err := m.GetFunctionForVMAddr(loc)
					if err != nil {
						log.Errorf("failed to get function for address: %v", err)
						continue
					}
					if !quiet {
						utils.Indent(log.WithFields(log.Fields{
							"file":    name,
							"address": fmt.Sprintf("%#09x", fn.StartAddr),
							"symbol":  sig.Symbol,
						}).Info, 2)("Symbolicated")
					}
					symbolMap[fn.StartAddr] = sig.Symbol
					found = true
					callerLoc := fn.StartAddr
					// attempt to symbolicate signature backtrace
					for _, caller := range sig.Backtrace {
						if ok, loc := engine.Contains(callerLoc); ok {
							fn, err := m.GetFunctionForVMAddr(loc)
							if err != nil {
								log.Errorf("failed to get function for address: %v", err)
								break // don't continue because we broke the caller chain (backtrace)
							}
							if !quiet {
								utils.Indent(log.WithFields(log.Fields{
									"file":    name,
									"address": fmt.Sprintf("%#09x", fn.StartAddr),
									"symbol":  caller,
								}).Info, 3)("Symbolicated (Caller)")
							}
							symbolMap[fn.StartAddr] = caller
							callerLoc = fn.StartAddr
						} else {
							if !quiet {
								utils.Indent(log.WithFields(log.Fields{
									"macho":  name,
									"caller": caller,
									"symbol": sig.Symbol,
								}).Warn, 2)("No XREFs to Caller found")
							}
							break
						}
					}
					break // found symbol so break out of anchor loop
				} else {
					if !quiet {
						utils.Indent(log.WithFields(log.Fields{
							"macho":  name,
							"anchor": truncate(strconv.Quote(anchor.String), 40),
							"symbol": sig.Symbol,
						}).Warn, 2)("XREF Not Found For Anchor")
					}
				}
			} else {
				if !quiet {
					utils.Indent(log.WithFields(log.Fields{
						"macho":  name,
						"anchor": truncate(strconv.Quote(anchor.String), 40),
						"symbol": sig.Symbol,
					}).Debug, 3)("Anchor Not Found")
				}
			}
		}
		if !found {
			if !quiet {
				utils.Indent(log.WithFields(log.Fields{
					"macho":  name,
					"symbol": sig.Symbol,
				}).Warn, 2)("Signature Not Matched")
			}
		}
	}

	log.WithFields(log.Fields{
		"total":   sigs.Total,
		"matched": len(symbolMap),
		"missed":  int(sigs.Total) - len(symbolMap),
		"percent": fmt.Sprintf("%.4f%%", 100*float64(len(symbolMap))/float64(sigs.Total)),
	}).Info("Symbolication STATS")

	return symbolMap, nil
}

func Symbolicate(infile string, sigs Symbolicator, quiet bool) (map[uint64]string, error) {
	m, err := macho.Open(infile)
	if err != nil {
		return nil, err
	}
	defer m.Close()

	if ok, err := CheckVersion(m, sigs); !ok {
		if err != nil {
			return nil, err
		}
		return nil, ErrUnsupportedVersion
	}

	if m.FileTOC.FileHeader.Type == types.MH_FILESET {
		m, err = m.GetFileSetFileByName(sigs.Target)
		if err != nil {
			return nil, err
		}
	} else {
		parts := strings.Split(sigs.Target, ".")
		if len(parts) > 1 {
			if !strings.HasPrefix(strings.ToLower(filepath.Base(infile)), strings.ToLower(parts[len(parts)-1])) {
				return nil, ErrUnsupportedTarget
			}
		}
	}

	return symbolicate(m, sigs.Target, sigs, quiet)
}
