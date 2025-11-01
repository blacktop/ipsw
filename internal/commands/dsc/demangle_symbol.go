package dsc

import "github.com/blacktop/ipsw/pkg/symbols"

// DemangleSymbolName wraps symbols.DemangleSymbolName for compatibility.
func DemangleSymbolName(name string) string {
	return symbols.DemangleSymbolName(name)
}

// DemangleBareSymbol wraps symbols.DemangleBareSymbol for compatibility.
func DemangleBareSymbol(name string) string {
	return symbols.DemangleBareSymbol(name)
}
