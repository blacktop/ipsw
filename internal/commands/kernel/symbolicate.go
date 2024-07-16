package kernel

//go:generate pkl-gen-go pkl/Symbolicator.pkl --base-path github.com/blacktop/ipsw --output-path ../../../

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"

	"github.com/apex/log"
	"github.com/blacktop/go-macho"
	"github.com/blacktop/go-macho/types"
	"github.com/blacktop/ipsw/internal/utils"
	"github.com/blacktop/ipsw/pkg/disass"
	"github.com/blacktop/ipsw/pkg/kernelcache"
	"github.com/blacktop/ipsw/pkg/signature"
	semver "github.com/hashicorp/go-version"
)

var UnsupportedVersion = errors.New("kernel version not supported")

func ParseSignatures(dir string) (sigs []*signature.Symbolicator, err error) {
	if err := filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if !info.IsDir() {
			if filepath.Ext(path) != ".pkl" {
				return nil
			}
			sig, err := signature.LoadFromPath(context.Background(), path)
			if err != nil {
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

func CheckKernelVersion(m *macho.File, sigs *signature.Symbolicator) (bool, error) {
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
		log.Fatal("failed to convert version into semver object")
	}
	maxVer, err := semver.NewVersion(sigs.Version.Max)
	if err != nil {
		log.Fatal("failed to convert version into semver object")
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

func symbolicate(m *macho.File, name string, sigs *signature.Symbolicator) (map[uint64]string, error) {
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

	var notFound int

	for _, sig := range sigs.Signatures {
		found := false
		for _, anchor := range sig.Anchors {
			if addr, ok := cstrs[fmt.Sprintf("%s.%s", anchor.Segment, anchor.Section)][anchor.String]; ok {
				log.WithFields(log.Fields{
					"pattern": truncate(strconv.Quote(anchor.String), 40),
					"address": fmt.Sprintf("%#09x", addr),
					"file":    name,
					"symbol":  sig.Symbol,
				}).Debug("Found Signature")
				if ok, loc := engine.Contains(addr); ok {
					fn, err := m.GetFunctionForVMAddr(loc)
					if err != nil {
						log.Errorf("failed to get function for address: %v", err)
						break
					}
					utils.Indent(log.WithFields(log.Fields{
						"file":    name,
						"address": fmt.Sprintf("%#09x", fn.StartAddr),
						"symbol":  sig.Symbol,
					}).Info, 2)("Symbolicated")
					symbolMap[fn.StartAddr] = sig.Symbol
					found = true
					if sig.Caller != "" {
						// attempt to symbolicate signature caller
						if ok, loc := engine.Contains(fn.StartAddr); ok {
							fn, err := m.GetFunctionForVMAddr(loc)
							if err != nil {
								log.Errorf("failed to get function for address: %v", err)
								break
							}
							utils.Indent(log.WithFields(log.Fields{
								"file":    name,
								"address": fmt.Sprintf("%#09x", fn.StartAddr),
								"symbol":  sig.Caller,
							}).Info, 2)("Symbolicated (Caller)")
							symbolMap[fn.StartAddr] = sig.Caller
						} else {
							utils.Indent(log.WithFields(log.Fields{
								"macho":  name,
								"caller": sig.Caller,
								"symbol": sig.Symbol,
							}).Warn, 2)("No XREFs to Caller found")
							notFound++
						}
					}
				}
				if found {
					break // break out of sig.Anchors loop
				} else {
					utils.Indent(log.WithFields(log.Fields{
						"macho":  name,
						"anchor": truncate(strconv.Quote(anchor.String), 40),
						"symbol": sig.Symbol,
					}).Warn, 2)("No XREFs found")
				}
			}
			if found {
				break // break out of cstr loop
			}
		}
		if !found {
			utils.Indent(log.WithFields(log.Fields{
				"macho":  name,
				"symbol": sig.Symbol,
			}).Warn, 2)("Signature Not Matched")
			notFound++
		}
	}

	log.WithFields(log.Fields{
		"total":   sigs.Total,
		"matched": fmt.Sprintf("%.4f%%", float64(int(sigs.Total)-notFound)*100/float64(sigs.Total)),
	}).Info("STATS")

	return symbolMap, nil
}

func Symbolicate(infile string, sigs *signature.Symbolicator) (map[uint64]string, error) {
	m, err := macho.Open(infile)
	if err != nil {
		return nil, err
	}
	defer m.Close()

	if ok, err := CheckKernelVersion(m, sigs); !ok {
		if err != nil {
			return nil, err
		}
		return nil, UnsupportedVersion
	}

	if m.FileTOC.FileHeader.Type == types.MH_FILESET {
		m, err = m.GetFileSetFileByName(sigs.Target)
		if err != nil {
			return nil, err
		}
	}

	return symbolicate(m, sigs.Target, sigs)
}
