package dyld

import (
	"fmt"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strings"

	"github.com/blacktop/ipsw/internal/demangle"
)

const defaultWebKitImage = "/System/Library/Frameworks/WebKit.framework/WebKit"

var (
	webkitIPCSymbolRE = regexp.MustCompile(`Messages::([A-Za-z_][A-Za-z0-9_]*)::([A-Za-z_][A-Za-z0-9_]*)`)
	webkitIPCIdentRE  = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)
)

// WebKitIPCConfig configures extraction of WebKit IPC message names from a DSC.
type WebKitIPCConfig struct {
	Image             string
	IncludeRawStrings bool
	IncludeSymbolOnly bool
	ReceiverPattern   string
	MessagePattern    string
}

// WebKitIPCRecord is one compiled WebKit IPC message name.
type WebKitIPCRecord struct {
	Address       uint64   `json:"address,omitempty"`
	SymbolAddress uint64   `json:"symbol_address,omitempty"`
	Receiver      string   `json:"receiver"`
	Message       string   `json:"message"`
	Name          string   `json:"name"`
	Section       string   `json:"section,omitempty"`
	Source        string   `json:"source"`
	Symbol        string   `json:"symbol,omitempty"`
	Symbols       []string `json:"symbols,omitempty"`
}

// WebKitIPCMessages dumps WebKit.framework IPC message-name strings from the shipping DSC image.
func WebKitIPCMessages(f *File, config WebKitIPCConfig) ([]WebKitIPCRecord, error) {
	imageName := config.Image
	if imageName == "" {
		imageName = defaultWebKitImage
	}

	image, err := webKitIPCImage(f, imageName)
	if err != nil {
		return nil, fmt.Errorf("image not in DSC: %w", err)
	}

	symbols := webKitIPCMessagesFromSymbols(image)
	recordsByName := make(map[string]WebKitIPCRecord)

	m, err := image.GetMacho()
	if err != nil {
		if config.IncludeSymbolOnly {
			return webKitIPCRecordsFromMap(symbols, config), nil
		}
		return nil, fmt.Errorf("failed to parse WebKit Mach-O: %w", err)
	}

	cstrings, err := m.GetCStrings()
	if err != nil {
		if config.IncludeSymbolOnly {
			return webKitIPCRecordsFromMap(symbols, config), nil
		}
		return nil, fmt.Errorf("failed to read WebKit cstrings: %w", err)
	}

	for section, sectionStrings := range cstrings {
		for value, addr := range sectionStrings {
			sym, hasSymbol := symbols[value]
			receiver, message, ok := parseWebKitIPCDescriptionString(value)
			if !ok {
				continue
			}
			name := receiver + "_" + message
			if hasSymbol {
				receiver = sym.Receiver
				message = sym.Message
				name = sym.Name
			} else {
				sym, hasSymbol = symbols[name]
			}
			if !hasSymbol && !config.IncludeRawStrings {
				continue
			}

			record := WebKitIPCRecord{
				Address:  addr,
				Receiver: receiver,
				Message:  message,
				Name:     name,
				Section:  section,
				Source:   "description",
			}
			if hasSymbol {
				record.SymbolAddress = sym.SymbolAddress
				record.Symbol = sym.Symbol
				record.Symbols = append([]string(nil), sym.Symbols...)
				record.Source = "description+symbol"
			}
			if existing, ok := recordsByName[name]; ok && existing.Address != 0 && existing.Address <= record.Address {
				continue
			}
			recordsByName[name] = record
		}
	}

	if config.IncludeSymbolOnly {
		for name, record := range symbols {
			if _, ok := recordsByName[name]; !ok {
				recordsByName[name] = record
			}
		}
	}

	return webKitIPCRecordsFromMap(recordsByName, config), nil
}

func webKitIPCMessagesFromSymbols(image *CacheImage) map[string]WebKitIPCRecord {
	records := make(map[string]WebKitIPCRecord)
	if image == nil {
		return records
	}

	_ = image.ParseLocalSymbols(false)
	for _, sym := range image.LocalSymbols {
		addWebKitIPCSymbol(records, sym.Name, sym.Value)
	}

	_ = image.ParsePublicSymbols(false)
	for _, sym := range image.PublicSymbols {
		addWebKitIPCSymbol(records, sym.Name, sym.Address)
	}

	return records
}

func addWebKitIPCSymbol(records map[string]WebKitIPCRecord, symbol string, addr uint64) {
	demangled := demangle.Do(symbol, false, false)
	for _, match := range webkitIPCSymbolRE.FindAllStringSubmatch(demangled, -1) {
		receiver := match[1]
		message := match[2]
		name := receiver + "_" + message
		record := records[name]
		if record.Name == "" {
			record = WebKitIPCRecord{
				Receiver: receiver,
				Message:  message,
				Name:     name,
				Source:   "symbol",
			}
		}
		record.Symbols = appendUniqueString(record.Symbols, demangled)
		if shouldReplaceWebKitIPCSymbol(record.SymbolAddress, addr) || record.Symbol == "" {
			record.SymbolAddress = addr
			record.Symbol = demangled
		}
		records[name] = record
	}
}

func shouldReplaceWebKitIPCSymbol(existing, candidate uint64) bool {
	if existing == 0 {
		return candidate != 0
	}
	if candidate == 0 {
		return false
	}
	return candidate < existing
}

func webKitIPCRecordLess(left, right WebKitIPCRecord) bool {
	if left.Address == right.Address {
		return left.Name < right.Name
	}
	if left.Address == 0 {
		return false
	}
	if right.Address == 0 {
		return true
	}
	return left.Address < right.Address
}

func parseWebKitIPCDescriptionString(value string) (string, string, bool) {
	idx := strings.LastIndex(value, "_")
	if idx <= 0 || idx == len(value)-1 {
		return "", "", false
	}
	receiver, message := value[:idx], value[idx+1:]
	if !webKitIPCIdentifier(receiver) || !webKitIPCIdentifier(message) {
		return "", "", false
	}
	if strings.Contains(receiver, "__") || strings.Contains(message, "__") {
		return "", "", false
	}
	return receiver, message, true
}

func webKitIPCIdentifier(value string) bool {
	return webkitIPCIdentRE.MatchString(value)
}

func webKitIPCRecordsFromMap(recordsByName map[string]WebKitIPCRecord, config WebKitIPCConfig) []WebKitIPCRecord {
	records := make([]WebKitIPCRecord, 0, len(recordsByName))
	for _, record := range recordsByName {
		if !webkitIPCRecordMatches(record, config) {
			continue
		}
		sort.Strings(record.Symbols)
		records = append(records, record)
	}
	sort.Slice(records, func(i, j int) bool {
		return webKitIPCRecordLess(records[i], records[j])
	})
	return records
}

func appendUniqueString(values []string, value string) []string {
	if value == "" {
		return values
	}
	if slices.Contains(values, value) {
		return values
	}
	return append(values, value)
}

func webKitIPCImage(f *File, name string) (*CacheImage, error) {
	if idx, err := f.GetDylibIndex(name); err == nil {
		return f.Images[idx], nil
	}

	var matches []*CacheImage
	for _, image := range f.Images {
		if strings.EqualFold(image.Name, name) || strings.EqualFold(filepath.Base(image.Name), name) {
			matches = append(matches, image)
		}
	}
	if len(matches) == 1 {
		return matches[0], nil
	}
	if len(matches) > 1 {
		names := make([]string, 0, len(matches))
		for _, match := range matches {
			names = append(names, match.Name)
		}
		sort.Strings(names)
		return nil, fmt.Errorf("multiple images matched %s; supply a full image path:\n\t- %s", name, strings.Join(names, "\n\t- "))
	}
	return nil, &ImageNotFoundError{Name: name}
}

func webkitIPCRecordMatches(record WebKitIPCRecord, config WebKitIPCConfig) bool {
	if config.ReceiverPattern != "" && !webkitIPCGlobMatch(record.Receiver, config.ReceiverPattern) {
		return false
	}
	if config.MessagePattern != "" && !webkitIPCGlobMatch(record.Message, config.MessagePattern) {
		return false
	}
	return true
}

func webkitIPCGlobMatch(value, pattern string) bool {
	if value == pattern {
		return true
	}
	if strings.Contains(value, pattern) {
		return true
	}
	matched, err := filepath.Match(pattern, value)
	return err == nil && matched
}
