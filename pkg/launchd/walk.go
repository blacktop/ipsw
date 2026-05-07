package launchd

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/blacktop/go-plist"
	"github.com/blacktop/ipsw/internal/commands/mount"
)

const (
	SourceKindLaunchdDaemon     = "launchd_daemon"
	SourceKindLaunchdAgent      = "launchd_agent"
	SourceKindNanoLaunchdDaemon = "nano_launchd_daemon"
	SourceKindXPCBundle         = "xpc_bundle"
	SourceKindAppXPC            = "app_xpc"
)

type ipswVolume struct {
	name string
	typ  string
}

type launchdPlistDir struct {
	kind string
	dir  string
}

var ipswFilesystemVolumes = []ipswVolume{
	{name: "AppOS", typ: "app"},
	{name: "FileSystem", typ: "fs"},
	{name: "SystemOS", typ: "sys"},
	{name: "ExclaveOS", typ: "exc"},
}

var launchdPlistDirs = []launchdPlistDir{
	{kind: SourceKindLaunchdDaemon, dir: "/System/Library/LaunchDaemons"},
	{kind: SourceKindLaunchdAgent, dir: "/System/Library/LaunchAgents"},
	{kind: SourceKindNanoLaunchdDaemon, dir: "/System/Library/NanoLaunchDaemons"},
}

var launchdCapturedTopLevelKeys = map[string]bool{
	"Label":              true,
	"Program":            true,
	"ProgramArguments":   true,
	"MachServices":       true,
	"SandboxProfile":     true,
	"POSIXSpawnType":     true,
	"ProcessType":        true,
	"CFBundleIdentifier": true,
}

var bundleCapturedTopLevelKeys = map[string]bool{
	"CFBundleIdentifier": true,
	"CFBundleExecutable": true,
	"Program":            true,
	"ProgramArguments":   true,
	"SeatbeltProfiles":   true,
	"POSIXSpawnType":     true,
	"ProcessType":        true,
}

type Record struct {
	SourceKind     string         `json:"source_kind"`
	PlistPath      string         `json:"plist_path"`
	Volume         string         `json:"volume"`
	PlistDigest    string         `json:"plist_digest"`
	Label          string         `json:"label"`
	Program        string         `json:"program"`
	BundleID       string         `json:"bundle_id"`
	MachServices   []string       `json:"mach_services"`
	SandboxProfile string         `json:"sandbox_profile"`
	ServiceType    string         `json:"service_type"`
	Extra          map[string]any `json:"extra"`
}

type IPSWConfig struct {
	PemDB string
}

type SkippedVolume struct {
	Volume string
	Type   string
	Err    error
}

func (s SkippedVolume) Error() string {
	if s.Err == nil {
		return fmt.Sprintf("%s: skipped", s.Volume)
	}
	return fmt.Sprintf("%s: %v", s.Volume, s.Err)
}

func WalkIPSW(path string, cfg *IPSWConfig) ([]Record, []SkippedVolume, error) {
	if cfg == nil {
		cfg = &IPSWConfig{}
	}

	var records []Record
	var skipped []SkippedVolume
	mounted := 0
	seenDMGs := make(map[string]struct{})

	for _, vol := range ipswFilesystemVolumes {
		ctx, err := mount.DmgInIPSW(path, vol.typ, &mount.Config{PemDB: cfg.PemDB})
		if err != nil {
			skipped = append(skipped, SkippedVolume{Volume: vol.name, Type: vol.typ, Err: err})
			continue
		}

		dmgPath := filepath.Clean(ctx.DmgPath)
		if _, seen := seenDMGs[dmgPath]; seen {
			if !ctx.AlreadyMounted {
				if err := ctx.Unmount(); err != nil {
					skipped = append(skipped, SkippedVolume{Volume: vol.name, Type: vol.typ, Err: fmt.Errorf("unmount failed: %w", err)})
				}
			}
			continue
		}
		seenDMGs[dmgPath] = struct{}{}
		mounted++

		volumeRecords, walkErr := WalkVolume(ctx.MountPoint, vol.name)
		var unmountErr error
		if !ctx.AlreadyMounted {
			unmountErr = ctx.Unmount()
		}
		if walkErr != nil {
			skipped = append(skipped, SkippedVolume{Volume: vol.name, Type: vol.typ, Err: walkErr})
			if unmountErr != nil {
				skipped = append(skipped, SkippedVolume{Volume: vol.name, Type: vol.typ, Err: fmt.Errorf("unmount failed: %w", unmountErr)})
			}
			continue
		}
		records = append(records, volumeRecords...)
		if unmountErr != nil {
			skipped = append(skipped, SkippedVolume{Volume: vol.name, Type: vol.typ, Err: fmt.Errorf("unmount failed: %w", unmountErr)})
		}
	}

	if mounted == 0 {
		return nil, skipped, errors.New("no IPSW filesystem DMGs mounted successfully")
	}
	SortRecords(records)
	return records, skipped, nil
}

func WalkVolume(root, volume string) ([]Record, error) {
	var candidates []plistCandidate
	seen := make(map[string]struct{})
	addCandidate := func(kind, path string) {
		rel := relativePlistPath(root, path)
		key := kind + "\x00" + rel
		if _, ok := seen[key]; ok {
			return
		}
		seen[key] = struct{}{}
		candidates = append(candidates, plistCandidate{kind: kind, path: path})
	}

	for _, spec := range launchdPlistDirs {
		matches, err := filepath.Glob(filepath.Join(root, filepath.FromSlash(spec.dir), "*.plist"))
		if err != nil {
			return nil, err
		}
		for _, match := range matches {
			addCandidate(spec.kind, match)
		}
	}

	if err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			if os.IsPermission(err) {
				return nil
			}
			return err
		}
		if d.IsDir() || d.Name() != "Info.plist" {
			return nil
		}
		rel := relativePlistPath(root, path)
		switch {
		case isXPCInfoPlist(rel):
			addCandidate(SourceKindXPCBundle, path)
		case strings.HasSuffix(rel, ".app/Info.plist"):
			addCandidate(SourceKindAppXPC, path)
		}
		return nil
	}); err != nil {
		return nil, err
	}

	sort.Slice(candidates, func(i, j int) bool {
		if candidates[i].path != candidates[j].path {
			return candidates[i].path < candidates[j].path
		}
		return candidates[i].kind < candidates[j].kind
	})

	records := make([]Record, 0, len(candidates))
	for _, candidate := range candidates {
		record, ok := recordFromFile(root, volume, candidate.kind, candidate.path)
		if ok {
			records = append(records, record)
		}
	}
	SortRecords(records)
	return records, nil
}

func EncodeJSONL(records []Record) ([]byte, error) {
	SortRecords(records)
	var buf bytes.Buffer
	for _, record := range records {
		line, err := MarshalRecord(record)
		if err != nil {
			return nil, err
		}
		buf.Write(line)
		buf.WriteByte('\n')
	}
	return buf.Bytes(), nil
}

func SortRecords(records []Record) {
	sort.SliceStable(records, func(i, j int) bool {
		if records[i].Volume != records[j].Volume {
			return records[i].Volume < records[j].Volume
		}
		if records[i].PlistPath != records[j].PlistPath {
			return records[i].PlistPath < records[j].PlistPath
		}
		return records[i].SourceKind < records[j].SourceKind
	})
}

func MarshalRecord(record Record) ([]byte, error) {
	if record.Extra == nil {
		record.Extra = map[string]any{}
	}
	top := map[string]any{
		"source_kind":     record.SourceKind,
		"plist_path":      record.PlistPath,
		"volume":          record.Volume,
		"plist_digest":    record.PlistDigest,
		"label":           record.Label,
		"program":         record.Program,
		"bundle_id":       record.BundleID,
		"mach_services":   sortedStringSlice(record.MachServices),
		"sandbox_profile": record.SandboxProfile,
		"service_type":    record.ServiceType,
		"extra":           canonicalJSONValue(record.Extra),
	}
	return marshalCompactJSON(top)
}

type plistCandidate struct {
	kind string
	path string
}

func recordFromFile(root, volume, sourceKind, path string) (Record, bool) {
	rel := relativePlistPath(root, path)
	raw, err := os.ReadFile(path)
	if err != nil {
		return parseErrorRecord(sourceKind, rel, volume, "", err), true
	}
	digest := rawDigest(raw)

	doc, canonicalDigest, err := parsePlist(raw)
	if err != nil {
		return parseErrorRecord(sourceKind, rel, volume, digest, err), true
	}
	digest = canonicalDigest

	if sourceKind == SourceKindAppXPC && !hasXPCService(doc) {
		return Record{}, false
	}

	record := Record{
		SourceKind:   sourceKind,
		PlistPath:    rel,
		Volume:       volume,
		PlistDigest:  digest,
		Label:        labelFor(sourceKind, doc),
		BundleID:     stringValue(doc["CFBundleIdentifier"]),
		MachServices: machServicesFor(sourceKind, doc),
		Program:      programFor(sourceKind, rel, doc),
		Extra:        extraFor(sourceKind, doc),
	}
	record.SandboxProfile = sandboxProfileFor(sourceKind, doc)
	record.ServiceType = serviceTypeFor(doc)
	return record, true
}

func parseErrorRecord(sourceKind, relPath, volume, digest string, err error) Record {
	return Record{
		SourceKind:   sourceKind,
		PlistPath:    relPath,
		Volume:       volume,
		PlistDigest:  digest,
		MachServices: []string{},
		Extra:        map[string]any{"parse_error": err.Error()},
	}
}

func parsePlist(raw []byte) (map[string]any, string, error) {
	var doc map[string]any
	if _, err := plist.Unmarshal(raw, &doc); err != nil {
		return nil, "", err
	}
	canonical, err := plist.Marshal(doc, plist.XMLFormat)
	if err != nil {
		return nil, "", err
	}
	sum := sha256.Sum256(canonical)
	return doc, hex.EncodeToString(sum[:]), nil
}

func rawDigest(raw []byte) string {
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}

func relativePlistPath(root, path string) string {
	rel, err := filepath.Rel(root, path)
	if err != nil {
		rel = path
	}
	return "/" + filepath.ToSlash(filepath.Clean(rel))
}

func isXPCInfoPlist(rel string) bool {
	return strings.HasSuffix(rel, ".xpc/Info.plist") ||
		strings.HasSuffix(rel, ".xpc/Contents/Info.plist")
}

func labelFor(sourceKind string, doc map[string]any) string {
	if isLaunchdKind(sourceKind) {
		return stringValue(doc["Label"])
	}
	return stringValue(doc["CFBundleIdentifier"])
}

func programFor(sourceKind, rel string, doc map[string]any) string {
	if program := stringValue(doc["Program"]); program != "" {
		return program
	}
	if args := stringSlice(doc["ProgramArguments"]); len(args) > 0 {
		return args[0]
	}
	executable := stringValue(doc["CFBundleExecutable"])
	if executable == "" {
		return ""
	}
	if strings.Contains(executable, "/") {
		return filepath.ToSlash(filepath.Clean(executable))
	}
	if sourceKind == SourceKindXPCBundle && strings.HasSuffix(rel, ".xpc/Contents/Info.plist") {
		return filepath.ToSlash(filepath.Join("Contents", "MacOS", executable))
	}
	return executable
}

func machServicesFor(sourceKind string, doc map[string]any) []string {
	if isLaunchdKind(sourceKind) {
		if machServices, ok := mapValue(doc["MachServices"]); ok {
			keys := make([]string, 0, len(machServices))
			for key := range machServices {
				keys = append(keys, key)
			}
			sort.Strings(keys)
			return keys
		}
		return []string{}
	}
	bundleID := stringValue(doc["CFBundleIdentifier"])
	if bundleID == "" {
		return []string{}
	}
	return []string{bundleID}
}

func sandboxProfileFor(sourceKind string, doc map[string]any) string {
	if isLaunchdKind(sourceKind) {
		return stringValue(doc["SandboxProfile"])
	}
	if profiles := stringSlice(doc["SeatbeltProfiles"]); len(profiles) > 0 {
		return profiles[0]
	}
	if xpc, ok := mapValue(doc["XPCService"]); ok {
		if profiles := stringSlice(xpc["SeatbeltProfiles"]); len(profiles) > 0 {
			return profiles[0]
		}
	}
	return ""
}

func serviceTypeFor(doc map[string]any) string {
	if xpc, ok := mapValue(doc["XPCService"]); ok {
		if serviceType := stringValue(xpc["ServiceType"]); serviceType != "" {
			return serviceType
		}
	}
	if spawnType := stringValue(doc["POSIXSpawnType"]); spawnType != "" {
		return spawnType
	}
	return stringValue(doc["ProcessType"])
}

func extraFor(sourceKind string, doc map[string]any) map[string]any {
	extra := make(map[string]any)
	captured := capturedTopLevelKeys(sourceKind)
	for key, value := range doc {
		if captured[key] {
			continue
		}
		if key == "XPCService" {
			if xpcExtra, ok := xpcServiceExtra(value); ok {
				extra[key] = xpcExtra
			}
			continue
		}
		extra[key] = value
	}
	return canonicalJSONValue(extra).(map[string]any)
}

func capturedTopLevelKeys(sourceKind string) map[string]bool {
	if isLaunchdKind(sourceKind) {
		return launchdCapturedTopLevelKeys
	}
	return bundleCapturedTopLevelKeys
}

func xpcServiceExtra(value any) (map[string]any, bool) {
	xpc, ok := mapValue(value)
	if !ok {
		return nil, false
	}
	out := make(map[string]any)
	for key, val := range xpc {
		if key == "ServiceType" || key == "SeatbeltProfiles" {
			continue
		}
		out[key] = val
	}
	if len(out) == 0 {
		return nil, false
	}
	return canonicalJSONValue(out).(map[string]any), true
}

func hasXPCService(doc map[string]any) bool {
	_, ok := mapValue(doc["XPCService"])
	return ok
}

func isLaunchdKind(sourceKind string) bool {
	switch sourceKind {
	case SourceKindLaunchdDaemon, SourceKindLaunchdAgent, SourceKindNanoLaunchdDaemon:
		return true
	default:
		return false
	}
}

func mapValue(v any) (map[string]any, bool) {
	m, ok := v.(map[string]any)
	return m, ok
}

func stringValue(v any) string {
	s, _ := stringValueOK(v)
	return s
}

func stringValueOK(v any) (string, bool) {
	switch value := v.(type) {
	case string:
		return value, true
	case fmt.Stringer:
		return value.String(), true
	default:
		return "", false
	}
}

func stringSlice(v any) []string {
	switch values := v.(type) {
	case []string:
		return append([]string(nil), values...)
	case []any:
		out := make([]string, 0, len(values))
		for _, value := range values {
			if s, ok := stringValueOK(value); ok {
				out = append(out, s)
			}
		}
		return out
	default:
		return nil
	}
}

func sortedStringSlice(values []string) []string {
	out := append([]string{}, values...)
	sort.Strings(out)
	return out
}

func canonicalJSONValue(v any) any {
	switch value := v.(type) {
	case map[string]any:
		out := make(map[string]any, len(value))
		for key, sub := range value {
			out[key] = canonicalJSONValue(sub)
		}
		return out
	case []any:
		out := make([]any, 0, len(value))
		for _, sub := range value {
			out = append(out, canonicalJSONValue(sub))
		}
		sort.Slice(out, func(i, j int) bool {
			return canonicalJSONKey(out[i]) < canonicalJSONKey(out[j])
		})
		return out
	case []string:
		out := append([]string(nil), value...)
		sort.Strings(out)
		return out
	case []byte:
		return base64.StdEncoding.EncodeToString(value)
	case time.Time:
		return value.UTC().Format(time.RFC3339Nano)
	default:
		return value
	}
}

func canonicalJSONKey(v any) string {
	data, err := marshalCompactJSON(v)
	if err != nil {
		return fmt.Sprintf("%T:%v", v, v)
	}
	return string(data)
}

func marshalCompactJSON(v any) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return nil, err
	}
	return bytes.TrimSuffix(buf.Bytes(), []byte("\n")), nil
}
