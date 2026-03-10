package signature

import (
	"fmt"

	"github.com/apex/log"
	"github.com/blacktop/go-macho"
	"github.com/blacktop/ipsw/pkg/kernelcache/cpp"
)

type kernelCPPSymbol struct {
	addr uint64
	name string
}

func (sm SymbolMap) addKernelCPPSymbols(kc *macho.File, quiet bool) (int, error) {
	if kc == nil {
		return 0, fmt.Errorf("nil kernelcache")
	}

	classes, err := cpp.NewScanner(kc, cpp.Config{}).Scan()
	if err != nil {
		return 0, fmt.Errorf("failed to discover C++ kernel symbols: %w", err)
	}

	added := sm.addKernelCPPClasses(classes)
	if added > 0 && !quiet {
		log.WithFields(log.Fields{
			"classes": len(classes),
			"added":   added,
		}).Info("Discovered C++ kernel symbols")
	}

	return added, nil
}

func (sm SymbolMap) addKernelCPPClasses(classes []cpp.Class) int {
	added := 0

	for _, class := range classes {
		for _, symbol := range cppClassSymbols(class) {
			if err := sm.Add(symbol.addr, symbol.name); err != nil {
				log.WithError(err).WithFields(log.Fields{
					"address": fmt.Sprintf("%#x", symbol.addr),
					"symbol":  symbol.name,
				}).Debug("Skipping conflicting C++ kernel symbol")
				continue
			}
			added++
		}
	}

	return added
}

func cppClassSymbols(class cpp.Class) []kernelCPPSymbol {
	if class.Name == "" {
		return nil
	}

	symbols := make([]kernelCPPSymbol, 0, 4)

	if class.Ctor != 0 {
		symbols = appendKernelCPPSymbol(symbols, class.Ctor, cppConstructorSymbol(class.Name))
	}
	if class.MetaPtr != 0 {
		symbols = appendKernelCPPSymbol(symbols, class.MetaPtr, cppMetaClassSymbol(class.Name))
	}
	if class.MetaVtableAddr != 0 {
		symbols = appendKernelCPPSymbol(symbols, class.MetaVtableAddr, cppMetaVtableSymbol(class.Name))
	}
	if class.VtableAddr != 0 {
		symbols = appendKernelCPPSymbol(symbols, class.VtableAddr, cppVtableSymbol(class.Name))
	}

	return symbols
}

func appendKernelCPPSymbol(symbols []kernelCPPSymbol, addr uint64, name string) []kernelCPPSymbol {
	if addr == 0 || name == "" {
		return symbols
	}
	return append(symbols, kernelCPPSymbol{
		addr: addr,
		name: name,
	})
}

func cppConstructorSymbol(className string) string {
	return fmt.Sprintf("%s::%s", className, className)
}

func cppMetaClassSymbol(className string) string {
	return className + "::gMetaClass"
}

func cppVtableSymbol(className string) string {
	return "vtable for " + className
}

func cppMetaVtableSymbol(className string) string {
	return "vtable for " + className + "::MetaClass"
}
