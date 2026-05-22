package ent

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"text/tabwriter"

	"github.com/apex/log"
	"github.com/blacktop/go-macho"
	"github.com/blacktop/go-plist"
	ents "github.com/blacktop/ipsw/internal/codesign/entitlements"
	"github.com/blacktop/ipsw/internal/search"
)

// FilesystemQuery configures direct filesystem entitlement searches.
type FilesystemQuery struct {
	PemDB        string
	KeyPattern   string
	ValuePattern string
	FilePattern  string
	Has          []string
	Without      []string
	FileOnly     bool
	Limit        int
	Format       string
}

type filesystemEntitlementRecord struct {
	Path         string       `json:"path"`
	Entitlements Entitlements `json:"entitlements,omitempty"`
	source       int
	order        int
}

// SearchFilesystemEntitlements walks IPSW filesystem DMGs or folders and prints matching Mach-O entitlements.
func SearchFilesystemEntitlements(ipsws, inputs []string, query FilesystemQuery) error {
	query.Has = normalizeEntitlementPatterns(query.Has)
	query.Without = normalizeEntitlementPatterns(query.Without)

	restoreLogLevel := suppressFilesystemProgressLogs(query)
	defer restoreLogLevel()

	var records []filesystemEntitlementRecord
	nextOrder := 0
	addRecord := func(path string, m *macho.File, source int) error {
		record, ok, err := entitlementRecordForMacho(path, m)
		if err != nil {
			log.Warnf("failed to parse entitlements for %s: %v", path, err)
			return nil
		}
		if !ok || !query.matches(record) {
			return nil
		}
		record.source = source
		record.order = nextOrder
		nextOrder++
		records = append(records, record)
		return nil
	}

	for idx, ipswPath := range ipsws {
		if err := search.ForEachMachoInIPSW(filepath.Clean(ipswPath), query.PemDB, func(path string, m *macho.File) error {
			return addRecord(path, m, idx)
		}); err != nil {
			return err
		}
	}

	for idx, inputPath := range inputs {
		root := absoluteInputRoot(inputPath)
		if err := search.ForEachMacho(root, func(path string, m *macho.File) error {
			return addRecord(filepath.Clean(path), m, len(ipsws)+idx)
		}); err != nil {
			return err
		}
	}

	sort.Slice(records, func(i, j int) bool {
		return filesystemRecordLess(records[i], records[j])
	})
	if query.Limit > 0 && len(records) > query.Limit {
		records = records[:query.Limit]
	}

	return printFilesystemEntitlements(records, query)
}

func absoluteInputRoot(inputPath string) string {
	root := filepath.Clean(inputPath)
	if abs, err := filepath.Abs(root); err == nil {
		return abs
	}
	return root
}

func filesystemRecordLess(left, right filesystemEntitlementRecord) bool {
	if left.Path != right.Path {
		return left.Path < right.Path
	}
	if left.source != right.source {
		return left.source < right.source
	}
	return left.order < right.order
}

func entitlementRecordForMacho(path string, m *macho.File) (filesystemEntitlementRecord, bool, error) {
	if m == nil || m.CodeSignature() == nil {
		return filesystemEntitlementRecord{}, false, nil
	}

	raw := m.CodeSignature().Entitlements
	if raw == "" && len(m.CodeSignature().EntitlementsDER) > 0 {
		decoded, err := ents.DerDecode(m.CodeSignature().EntitlementsDER)
		if err != nil {
			return filesystemEntitlementRecord{}, false, err
		}
		raw = decoded
	}
	if raw == "" {
		return filesystemEntitlementRecord{}, false, nil
	}

	entitlements, err := parseEntitlementPlist(raw)
	if err != nil {
		return filesystemEntitlementRecord{}, false, err
	}
	if len(entitlements) == 0 {
		return filesystemEntitlementRecord{}, false, fmt.Errorf("decoded entitlement blob had no keys")
	}

	return filesystemEntitlementRecord{
		Path:         path,
		Entitlements: entitlements,
	}, true, nil
}

func parseEntitlementPlist(raw string) (Entitlements, error) {
	entitlements := make(Entitlements)
	if err := plist.NewDecoder(bytes.NewReader([]byte(raw))).Decode(&entitlements); err != nil {
		return nil, err
	}
	return entitlements, nil
}

func (query FilesystemQuery) matches(record filesystemEntitlementRecord) bool {
	if query.FilePattern != "" && !contains(record.Path, query.FilePattern) {
		return false
	}

	if !entitlementsHaveAll(record.Entitlements, query.Has) {
		return false
	}
	if entitlementsHaveAny(record.Entitlements, query.Without) {
		return false
	}

	if query.KeyPattern != "" && !entitlementsHaveAnyPattern(record.Entitlements, []string{query.KeyPattern}) {
		return false
	}
	if query.ValuePattern != "" && !entitlementValueMatches(record.Entitlements, query.ValuePattern) {
		return false
	}

	return true
}

func entitlementsHaveAll(entitlements Entitlements, patterns []string) bool {
	for _, pattern := range patterns {
		if !entitlementsHaveKey(entitlements, pattern) {
			return false
		}
	}
	return true
}

func entitlementsHaveAny(entitlements Entitlements, patterns []string) bool {
	if len(patterns) == 0 {
		return false
	}
	for _, pattern := range patterns {
		if entitlementsHaveKey(entitlements, pattern) {
			return true
		}
	}
	return false
}

func entitlementsHaveKey(entitlements Entitlements, pattern string) bool {
	for key := range entitlements {
		if entitlementKeyMatch(key, pattern) {
			return true
		}
	}
	return false
}

func entitlementsHaveAnyPattern(entitlements Entitlements, patterns []string) bool {
	for key := range entitlements {
		for _, pattern := range patterns {
			if entitlementPatternMatch(key, pattern) {
				return true
			}
		}
	}
	return false
}

func entitlementValueMatches(entitlements Entitlements, pattern string) bool {
	for _, value := range entitlements {
		switch v := value.(type) {
		case string:
			if contains(v, pattern) {
				return true
			}
		case bool:
			if contains(fmt.Sprintf("%t", v), pattern) {
				return true
			}
		default:
			data, err := json.Marshal(v)
			if err == nil && contains(string(data), pattern) {
				return true
			}
		}
	}
	return false
}

func entitlementPatternMatch(value, pattern string) bool {
	if value == pattern {
		return true
	}
	if strings.ContainsAny(pattern, "*?[") {
		if matched, err := filepath.Match(pattern, value); err == nil && matched {
			return true
		}
	}
	return contains(value, pattern)
}

func entitlementKeyMatch(value, pattern string) bool {
	if value == pattern {
		return true
	}
	if strings.ContainsAny(pattern, "*?[") {
		matched, err := filepath.Match(pattern, value)
		return err == nil && matched
	}
	return false
}

func normalizeEntitlementPatterns(values []string) []string {
	var out []string
	for _, value := range values {
		for part := range strings.SplitSeq(value, ",") {
			part = strings.TrimSpace(part)
			if part != "" {
				out = append(out, part)
			}
		}
	}
	return out
}

func printFilesystemEntitlements(records []filesystemEntitlementRecord, query FilesystemQuery) error {
	switch query.Format {
	case "", "text":
		return printFilesystemText(records, query.FileOnly)
	case "tsv":
		return printFilesystemTSV(records, query.FileOnly)
	case "jsonl":
		return printFilesystemJSONL(records, query.FileOnly)
	default:
		return fmt.Errorf("--format must be one of: text, tsv, jsonl")
	}
}

func printFilesystemText(records []filesystemEntitlementRecord, fileOnly bool) error {
	if fileOnly {
		for _, record := range records {
			fmt.Println(colorBin(record.Path))
		}
		return nil
	}

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 1, ' ', 0)
	for _, record := range records {
		data, err := json.Marshal(record.Entitlements)
		if err != nil {
			return err
		}
		fmt.Fprintf(w, "%s\t%s\n", colorBin(record.Path), colorValue(string(data)))
	}
	return w.Flush()
}

func printFilesystemTSV(records []filesystemEntitlementRecord, fileOnly bool) error {
	for _, record := range records {
		if fileOnly {
			fmt.Println(record.Path)
			continue
		}
		data, err := json.Marshal(record.Entitlements)
		if err != nil {
			return err
		}
		fmt.Printf("%s\t%s\n", record.Path, string(data))
	}
	return nil
}

func printFilesystemJSONL(records []filesystemEntitlementRecord, fileOnly bool) error {
	return printFilesystemJSONLTo(os.Stdout, records, fileOnly)
}

func printFilesystemJSONLTo(w io.Writer, records []filesystemEntitlementRecord, fileOnly bool) error {
	enc := json.NewEncoder(w)
	for _, record := range records {
		if fileOnly {
			if err := enc.Encode(struct {
				Path string `json:"path"`
			}{Path: record.Path}); err != nil {
				return err
			}
			continue
		}
		if err := enc.Encode(record); err != nil {
			return err
		}
	}
	return nil
}

func suppressFilesystemProgressLogs(query FilesystemQuery) func() {
	if !query.FileOnly && query.Format != "jsonl" && query.Format != "tsv" {
		return func() {}
	}
	logger, ok := log.Log.(*log.Logger)
	if !ok || logger.Level <= log.DebugLevel {
		return func() {}
	}
	oldLevel := logger.Level
	log.SetLevel(log.WarnLevel)
	return func() {
		log.SetLevel(oldLevel)
	}
}
