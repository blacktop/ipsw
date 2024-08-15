package signature

import (
	"encoding/json"
	"fmt"
	"maps"
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
)

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

type SymbolMap map[uint64]string

func NewSymbolMap() SymbolMap {
	return make(SymbolMap)
}

func (sm SymbolMap) LoadJSON(infile string) error {
	data, err := os.ReadFile(infile)
	if err != nil {
		return fmt.Errorf("failed to read file: %v", err)
	}
	if err := json.Unmarshal(data, &sm); err != nil {
		return fmt.Errorf("failed to unmarshal json: %v", err)
	}
	return nil
}

func (sm SymbolMap) Add(addr uint64, symbol string) error {
	if sym, ok := sm[addr]; ok {
		if sym == symbol || sym == symbol+"_trap" {
			return nil // NOP
		}
		return fmt.Errorf("%#x already has symbol '%s', cannot add symbol '%s'", addr, sym, symbol)
	}
	sm[addr] = symbol
	return nil
}

func (sm SymbolMap) overwrite(addr uint64, symbol string) {
	sm[addr] = symbol
}

func (sm SymbolMap) Copy(m map[uint64]string) {
	maps.Copy(sm, m)
}

func (sm SymbolMap) symbolicate(m *macho.File, name string, sigs Symbolicator, quiet bool) error {

	sigs.Total += uint(len(sm))

	seen := make(map[string]bool)

	text := m.Section("__TEXT_EXEC", "__text")
	if text == nil {
		return fmt.Errorf("failed to find __TEXT_EXEC.__text section")
	}
	data, err := text.Data()
	if err != nil {
		return fmt.Errorf("failed to get data from __TEXT_EXEC.__text section: %v", err)
	}

	engine := disass.NewMachoDisass(m, &map[uint64]string{}, &disass.Config{
		Data:         data,
		StartAddress: text.Addr,
		Quite:        true,
	})

	log.WithField("name", name).Info("Analyzing MachO...")
	if err := engine.Triage(); err != nil {
		return fmt.Errorf("first pass triage failed: %v", err)
	}

	cstrs, err := m.GetCStrings()
	if err != nil {
		return fmt.Errorf("failed to get cstrings: %v", err)
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
					if err := sm.Add(fn.StartAddr, sig.Symbol); err != nil {
						utils.Indent(log.WithError(err).Debug, 3)("failed to add to symbol map")
						// return fmt.Errorf("failed to add to symbol map: %v", err)
					}
					found = true
					// attempt to symbolicate signature backtrace
					callerLoc := fn.StartAddr
					for _, caller := range sig.Backtrace {
						if !seen[caller] {
							if ok, loc := engine.Contains(callerLoc); ok {
								fcn, err := m.GetFunctionForVMAddr(loc)
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
								if err := sm.Add(fcn.StartAddr, caller); err != nil {
									utils.Indent(log.WithError(err).WithField("signature", sig.Symbol).Debug, 4)("failed to add 'caller' to symbol map")
									// return nil, fmt.Errorf("failed to add 'caller' to symbol map (for signature '%s'): %v", sig.Symbol, err)
								}
								callerLoc = fcn.StartAddr
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
							seen[caller] = true
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
		"matched": len(sm),
		"missed":  int(sigs.Total) - len(sm),
		"percent": fmt.Sprintf("%.4f%%", 100*float64(len(sm))/float64(sigs.Total)),
	}).Info("📈 Symbolication STATS")

	return nil
}

func (sm SymbolMap) getSyscalls(m *macho.File) error {
	syscalls, err := kernelcache.GetSyscallTable(m)
	if err != nil {
		return err
	}

	for _, syscall := range syscalls {
		if syscall.Name == "syscall" || syscall.Name == "enosys" {
			continue
		}
		if err := sm.Add(syscall.Call, syscall.Name); err != nil {
			utils.Indent(log.WithError(err).Debug, 2)("Adding syscall")
		}
	}

	return nil
}

func (sm SymbolMap) getMachTraps(m *macho.File) error {
	machtraps, err := kernelcache.GetMachTrapTable(m)
	if err != nil {
		return fmt.Errorf("failed to get mach trap table: %v", err)
	}

	for _, machtrap := range machtraps {
		if machtrap.Name == "kern_invalid" {
			continue
		}
		if err := sm.Add(machtrap.Function, machtrap.Name+"_trap"); err != nil {
			utils.Indent(log.WithError(err).Debug, 2)("Adding mach_trap")
		}
	}

	return nil
}

func (sm SymbolMap) getMig(m *macho.File) error {
	migs, err := kernelcache.GetMigSubsystems(m)
	if err != nil {
		return fmt.Errorf("failed to get MIG subsystems: %v", err)
	}

	for _, mig := range migs {
		if err := sm.Add(mig.KServer, strings.TrimSuffix(mig.Start.String(), "_subsystem")+"_server_routine"); err != nil {
			utils.Indent(log.WithError(err).Debug, 2)("Adding mig server_routine")
		}
		for idx, routine := range mig.Routines {
			if routine.KStubRoutine != 0 {
				if err := sm.Add(routine.KStubRoutine, mig.LookupRoutineName(idx)); err != nil {
					utils.Indent(log.WithError(err).Debug, 2)("Adding mig routine")
				}
			}
		}
	}

	return nil
}

func (sm SymbolMap) Symbolicate(infile string, sigs []Symbolicator, quiet bool) error {
	kc, err := macho.Open(infile)
	if err != nil {
		return fmt.Errorf("failed to open kernelcache: %v", err)
	}
	defer kc.Close()

	kv, err := kernelcache.GetVersion(kc)
	if err != nil {
		return fmt.Errorf("failed to get kernelcache version: %v", err)
	}

	if err := sm.getSyscalls(kc); err != nil {
		log.WithError(err).Warn("failed to get syscalls")
	}
	if err := sm.getMachTraps(kc); err != nil {
		log.WithError(err).Warn("failed to get mach traps")
	}
	if err := sm.getMig(kc); err != nil {
		log.WithError(err).Warn("failed to get MIG subsystems")
	}

	goodsig := false

	for _, sig := range sigs {
		if ok, err := checkVersion(kv, sig); !ok {
			continue
		} else if err != nil {
			return err
		}
		// TODO: add support for OLD non-fileset KEXTs
		if kc.FileTOC.FileHeader.Type == types.MH_FILESET {
			m, err := kc.GetFileSetFileByName(sig.Target)
			if err != nil {
				continue // fileset doesn't contain target
			}
			// symbolicate with signature
			if err := sm.symbolicate(m, sig.Target, sig, quiet); err != nil {
				return err
			}
		} else {
			parts := strings.Split(sig.Target, ".")
			if len(parts) > 1 {
				// check if target macho file matches signature target
				if !strings.HasPrefix(strings.ToLower(filepath.Base(infile)), strings.ToLower(parts[len(parts)-1])) {
					continue
				}
			}
			// symbolicate with signature
			if err := sm.symbolicate(kc, sig.Target, sig, quiet); err != nil {
				return err
			}
		}

		goodsig = true
	}

	if !goodsig {
		return fmt.Errorf("no valid signatures found for kernelcache (let author know and we can try add them)")
	}

	return nil
}
