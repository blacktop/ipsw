package kernel

//go:generate pkl-gen-go pkl/Symbolicator.pkl --base-path github.com/blacktop/ipsw --output-path ../../../

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

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

func xrefs(m *macho.File, addr uint64) error {
	xrefs := make(map[uint64]string)
	symbolMap := make(map[uint64]string)

	utils.Indent(log.Debug, 2)(fmt.Sprintf("Searching for xrefs to: %#x", addr))

	for _, fn := range m.GetFunctions() {
		data, err := m.GetFunctionData(fn)
		if err != nil {
			log.Errorf("failed to get data for function: %v", err)
			continue
		}

		engine := disass.NewMachoDisass(m, &symbolMap, &disass.Config{
			Data:         data,
			StartAddress: fn.StartAddr,
		})

		if err := engine.Triage(); err != nil {
			return fmt.Errorf("first pass triage failed: %v", err)
		}

		if ok, loc := engine.Contains(addr); ok {
			if syms, err := m.FindAddressSymbols(fn.StartAddr); err == nil {
				if len(syms) > 0 {
					symbolMap[loc] = syms[0].Name
				}
				xrefs[loc] = fmt.Sprintf("%s + %d", syms[0].Name, loc-fn.StartAddr)
			} else {
				xrefs[loc] = fmt.Sprintf("func_%x + %d", fn.StartAddr, loc-fn.StartAddr)
			}
		}
	}

	for loc, sym := range xrefs {
		utils.Indent(log.WithFields(log.Fields{
			"address": fmt.Sprintf("%#09x", loc),
			"symbol":  sym,
		}).Info, 2)("XREF")
	}

	return nil
}

func symbolicate(m *macho.File, name string, sigs *signature.Symbolicator) error {
	cstrs, err := m.GetCStrings()
	if err != nil {
		return err
	}
	for _, sig := range sigs.Signatures {
		for addr, s := range cstrs {
			if strings.Contains(s, sig.Pattern) {
				log.WithFields(log.Fields{
					"pattern": s,
					"address": fmt.Sprintf("%#09x", addr),
					"file":    name,
				}).Info("Found Signature")
				if err := xrefs(m, addr); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

func Symbolicate(in string, sigs *signature.Symbolicator) error {
	m, err := macho.Open(in)
	if err != nil {
		return err
	}
	defer m.Close()

	if m.FileTOC.FileHeader.Type == types.MH_FILESET {
		for _, fs := range m.FileSets() {
			entry, err := m.GetFileSetFileByName(fs.EntryID)
			if err != nil {
				return err
			}
			if err := symbolicate(entry, fs.EntryID, sigs); err != nil {
				return err
			}
		}
	} else {
		if err := symbolicate(m, filepath.Base(in), sigs); err != nil {
			return err
		}
	}

	return nil
}
