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
	HandlerClass  string   `json:"handler_class,omitempty"`
	ArgTypes      []string `json:"arg_types,omitempty"`
	WorkQueue     bool     `json:"work_queue,omitempty"`
}

// WebKitIPCMessages dumps WebKit.framework IPC message-name strings from the shipping DSC image.
func WebKitIPCMessages(f *File, config WebKitIPCConfig) ([]WebKitIPCRecord, error) {
	imageName := config.Image
	if imageName == "" {
		imageName = defaultWebKitImage
	}

	image, err := cacheImageByName(f, imageName)
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
		if handlerClass, argTypes, workQueue, ok := webKitIPCHandlerInfo(demangled); ok {
			if record.HandlerClass == "" {
				record.HandlerClass = handlerClass
			}
			for _, argType := range argTypes {
				record.ArgTypes = appendUniqueString(record.ArgTypes, argType)
			}
			record.WorkQueue = record.WorkQueue || workQueue
		}
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
		sort.Strings(record.ArgTypes)
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

func webKitIPCHandlerInfo(symbol string) (string, []string, bool, bool) {
	if !strings.Contains(symbol, "IPC::handleMessage") {
		return "", nil, false, false
	}
	templateArgs, ok := templateArgumentsAfter(symbol, "IPC::handleMessage")
	if !ok {
		return "", nil, strings.Contains(symbol, "WorkQueueMessageReceiver"), false
	}
	parts := splitTopLevel(templateArgs, ',')
	if len(parts) < 2 {
		return "", nil, strings.Contains(symbol, "WorkQueueMessageReceiver"), false
	}
	handlerClass := strings.TrimSpace(parts[1])
	argTypes := memberFunctionPointerArgTypes(parts)
	workQueue := strings.Contains(symbol, "WorkQueueMessageReceiver") || strings.Contains(handlerClass, "WorkQueueMessageReceiver")
	return handlerClass, argTypes, workQueue, handlerClass != "" || len(argTypes) > 0 || workQueue
}

func templateArgumentsAfter(symbol, name string) (string, bool) {
	idx := strings.Index(symbol, name)
	if idx < 0 {
		return "", false
	}
	start := strings.Index(symbol[idx:], "<")
	if start < 0 {
		return "", false
	}
	start += idx
	depth := 0
	for pos := start; pos < len(symbol); pos++ {
		switch symbol[pos] {
		case '<':
			depth++
		case '>':
			depth--
			if depth == 0 {
				return symbol[start+1 : pos], true
			}
		}
	}
	return "", false
}

func memberFunctionPointerArgTypes(parts []string) []string {
	for _, part := range parts {
		idx := strings.Index(part, "::*)(")
		if idx < 0 {
			continue
		}
		start := idx + len("::*)(")
		end := matchingParenIndex(part, start-1)
		if end <= start {
			continue
		}
		args := strings.TrimSpace(part[start:end])
		if args == "" || args == "void" {
			return nil
		}
		return trimStrings(splitTopLevel(args, ','))
	}
	return nil
}

func matchingParenIndex(value string, open int) int {
	if open < 0 || open >= len(value) || value[open] != '(' {
		return -1
	}
	depth := 0
	for idx := open; idx < len(value); idx++ {
		switch value[idx] {
		case '(':
			depth++
		case ')':
			depth--
			if depth == 0 {
				return idx
			}
		}
	}
	return -1
}

func splitTopLevel(value string, sep byte) []string {
	var out []string
	start := 0
	angleDepth := 0
	parenDepth := 0
	for idx := 0; idx < len(value); idx++ {
		switch value[idx] {
		case '<':
			angleDepth++
		case '>':
			if angleDepth > 0 {
				angleDepth--
			}
		case '(':
			parenDepth++
		case ')':
			if parenDepth > 0 {
				parenDepth--
			}
		case sep:
			if angleDepth == 0 && parenDepth == 0 {
				out = append(out, strings.TrimSpace(value[start:idx]))
				start = idx + 1
			}
		}
	}
	out = append(out, strings.TrimSpace(value[start:]))
	return out
}

func trimStrings(values []string) []string {
	out := values[:0]
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value != "" {
			out = append(out, value)
		}
	}
	return out
}

func cacheImageByName(f *File, name string) (*CacheImage, error) {
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
