package kernel

//go:generate pkl-gen-go pkl/Symbolicator.pkl --base-path github.com/blacktop/ipsw --output-path ../../../

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strconv"

	"github.com/apex/log"
	"github.com/blacktop/go-macho"
	"github.com/blacktop/go-macho/types"
	"github.com/blacktop/ipsw/internal/utils"
	"github.com/blacktop/ipsw/pkg/disass"
	"github.com/blacktop/ipsw/pkg/signature"
)

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

func truncate(in string, length int) string {
	if len(in) > length {
		return in[:length] + "..."
	}
	return in
}

func symbolicate(m *macho.File, name string, sigs *signature.Symbolicator) error {
	symbolMap := make(map[uint64]string)

	text := m.Section("__TEXT_EXEC", "__text")
	if text == nil {
		return fmt.Errorf("failed to find __TEXT_EXEC.__text section")
	}
	data, err := text.Data()
	if err != nil {
		return fmt.Errorf("failed to get data from __TEXT_EXEC.__text section: %v", err)
	}

	engine := disass.NewMachoDisass(m, &symbolMap, &disass.Config{
		Data:         data,
		StartAddress: text.Addr,
	})

	log.WithField("name", name).Info("Analyzing MachO...")
	if err := engine.Triage(); err != nil {
		return fmt.Errorf("first pass triage failed: %v", err)
	}

	cstrs, err := m.GetCStrings()
	if err != nil {
		return err
	}

	for _, sig := range sigs.Signatures {
		found := false
		for addr, s := range cstrs {
			for _, anchor := range sig.Anchors {
				if s == anchor {
					log.WithFields(log.Fields{
						"pattern": truncate(strconv.Quote(s), 40),
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
						found = true
					}
					if found {
						break // break out of sig.Anchors loop
					} else {
						utils.Indent(log.WithFields(log.Fields{
							"macho":  name,
							"anchor": truncate(strconv.Quote(anchor), 40),
							"symbol": sig.Symbol,
						}).Warn, 2)("No xrefs found")
					}
				}
			}
			if found {
				break // break out of cstr loop
			}
		}
	}
	return nil
}

func Symbolicate(infile string, sigs *signature.Symbolicator) error {
	m, err := macho.Open(infile)
	if err != nil {
		return err
	}
	defer m.Close()

	if m.FileTOC.FileHeader.Type == types.MH_FILESET {
		m, err = m.GetFileSetFileByName(sigs.Target)
		if err != nil {
			return err
		}
	}

	if err := symbolicate(m, sigs.Target, sigs); err != nil {
		return err
	}

	return nil
}