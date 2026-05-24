//go:build sandbox

package sb

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/MakeNowJust/heredoc/v2"
	"github.com/apex/log"
	"github.com/blacktop/go-macho"
	"github.com/blacktop/go-plist"
	ents "github.com/blacktop/ipsw/internal/codesign/entitlements"
	"github.com/blacktop/ipsw/internal/search"
	"github.com/blacktop/ipsw/internal/utils"
	"github.com/blacktop/ipsw/pkg/kernel/iokit"
	"github.com/blacktop/ipsw/pkg/launchd"
	sbgraph "github.com/blacktop/ipsw/pkg/sandbox/graph"
	"github.com/spf13/cobra"
)

func init() {
	SbCmd.AddCommand(sbReachCmd)

	flags := sbReachCmd.Flags()
	flags.String("graph", "", "Use a previously exported sandbox graph instead of building from live sandbox inputs")
	flags.Bool("profile-bin", false, "Build graph from a compiled sandbox profile instead of the builtin collection")
	flags.StringP("input", "i", "", "Input sandbox profile binary file")
	flags.StringP("operations", "o", "", "Input operations list file (one operation per line)")
	flags.String("darwin-version", "", "Darwin version when using --operations without a kernelcache")
	flags.StringP("output", "O", "tsv", "Output format: tsv or jsonl")
	flags.Bool("join-launchd", false, "Join reachable mach names to launchd/XPC metadata")
	flags.String("launchd-jsonl", "", "Path to ipsw launchd JSONL output")
	flags.String("ipsw", "", "IPSW to scan for launchd metadata when --join-launchd is set")
	flags.String("pem-db", "", "AEA PEM DB JSON file path when --ipsw is used")
	flags.Bool("join-ent", false, "Join daemon Mach-O entitlements from --fs-root")
	flags.String("fs-root", "", "Mounted or extracted OS filesystem root for daemon entitlement lookup")
	flags.Bool("join-sb", false, "Include daemon sandbox profile from launchd metadata")
	flags.Bool("iokit", false, "Include iokit-open reachability rows")
	flags.String("iokit-methods-jsonl", "", "Path to ipsw kernel iokit-methods JSONL for kext-bundle joins")
	sbReachCmd.MarkZshCompPositionalArgumentFile(2, "kernelcache*")
}

var sbReachCmd = &cobra.Command{
	Use:   "reach <PROFILE> [KERNELCACHE]",
	Short: "Emit mach-lookup reachability rows for a sandbox profile",
	Long: heredoc.Doc(`
		Emit one row per reachable mach service, preserving the residual gate
		condition after the mach-name predicate is removed. With joins enabled,
		the output becomes one row per serving daemon.

		The fast path is to export the graph once and reuse it:

		  ipsw sb graph export kernelcache.release.iPhone18,1 -O graph.json
		  ipsw launchd iPhone18,1_26.0_23A5276f_Restore.ipsw > launchd.jsonl
		  ipsw sb reach com.apple.WebKit.WebContent --graph graph.json \
		    --join-launchd --launchd-jsonl launchd.jsonl \
		    --join-ent --fs-root /Volumes/SystemOS \
		    --join-sb
	`),
	Example: heredoc.Doc(`
		# Just mach names and gate conditions
		❯ ipsw sb reach com.apple.WebKit.WebContent --graph graph.json

		# Join to launchd JSONL and daemon entitlements from a mounted root
		❯ ipsw sb reach com.apple.WebKit.WebContent --graph graph.json \
		    --join-launchd --launchd-jsonl launchd.jsonl \
		    --join-ent --fs-root /Volumes/SystemOS --join-sb`),
	Args:          cobra.RangeArgs(1, 2),
	SilenceErrors: true,
	Hidden:        true,
	RunE: func(cmd *cobra.Command, args []string) error {
		graph, err := loadGraphForReachCommand(cmd, args[1:])
		if err != nil {
			return err
		}

		matches := reachMatchesForProfile(graph, args[0])
		includeIOKit, _ := cmd.Flags().GetBool("iokit")
		var iokitBundles *iokitBundleJoiner
		if includeIOKit {
			matches = append(matches, iokitReachMatchesForProfile(graph, args[0])...)
			matches = sortAndCompactReachMatches(matches)
			iokitBundles, err = loadIOKitBundleJoiner(cmd, args[1:])
			if err != nil {
				return err
			}
		}
		if len(matches) == 0 {
			kind := "mach-lookup"
			if includeIOKit {
				kind = "mach-lookup or iokit-open"
			}
			return fmt.Errorf("profile %q has no reachable %s allow rows", args[0], kind)
		}

		joinLaunchd, _ := cmd.Flags().GetBool("join-launchd")
		joinEnt, _ := cmd.Flags().GetBool("join-ent")
		joinSB, _ := cmd.Flags().GetBool("join-sb")
		if joinSB && !joinLaunchd {
			return fmt.Errorf("--join-sb requires --join-launchd")
		}
		if joinEnt && !joinLaunchd {
			return fmt.Errorf("--join-ent requires --join-launchd so daemon paths can be resolved")
		}

		var launchdRows []launchd.Record
		if joinLaunchd {
			launchdRows, err = loadLaunchdJoinRecords(cmd)
			if err != nil {
				return err
			}
		}

		var entitlements *entitlementJoiner
		if joinEnt {
			entitlements, err = loadEntitlementJoiner(cmd, matches, launchdRows)
			if err != nil {
				return err
			}
		}

		rows := reachRows(matches, launchdRows, entitlements, iokitBundles, joinLaunchd, joinSB)
		outputFormat, _ := cmd.Flags().GetString("output")
		switch strings.ToLower(strings.TrimSpace(outputFormat)) {
		case "", "tsv":
			if includeIOKit {
				return writeReachExtendedTSV(os.Stdout, rows)
			}
			return writeReachTSV(os.Stdout, rows)
		case "jsonl":
			return writeReachJSONL(os.Stdout, rows)
		default:
			return fmt.Errorf("unsupported --output %q (expected tsv or jsonl)", outputFormat)
		}
	},
}

type reachMatch struct {
	Operation     string
	Target        string
	MachName      string
	GateCondition string
}

type reachRow struct {
	Operation            string `json:"operation,omitempty"`
	Target               string `json:"target,omitempty"`
	MachName             string `json:"mach_name,omitempty"`
	GateCondition        string `json:"gate_condition"`
	DaemonPath           string `json:"daemon_path,omitempty"`
	DaemonEntitlements   string `json:"daemon_ents_json,omitempty"`
	DaemonSandboxProfile string `json:"daemon_sb_profile,omitempty"`
	HardenedProcess      string `json:"hardened_process,omitempty"`
	KextBundle           string `json:"kext_bundle,omitempty"`
}

type directReachState struct {
	matches         []reachMatch
	deniedMachNames map[string]struct{}
	denyWildcard    bool
	hasDefer        bool
}

func loadGraphForReachCommand(cmd *cobra.Command, args []string) (*sbgraph.Graph, error) {
	graphPath, _ := cmd.Flags().GetString("graph")
	if graphPath != "" {
		if len(args) > 0 {
			return nil, fmt.Errorf("--graph and a kernelcache argument are mutually exclusive")
		}
		return loadGraphFromFile(graphPath, "")
	}
	return buildGraphFromSandboxInputs(args, reachGraphOptionsFromCommand(cmd))
}

func reachGraphOptionsFromCommand(cmd *cobra.Command) graphInputOptions {
	profileBin, _ := cmd.Flags().GetBool("profile-bin")
	input, _ := cmd.Flags().GetString("input")
	operations, _ := cmd.Flags().GetString("operations")
	darwinVersion, _ := cmd.Flags().GetString("darwin-version")
	return graphInputOptions{
		singleProfile: profileBin,
		profileInput:  input,
		operations:    operations,
		darwinVersion: darwinVersion,
	}
}

func reachMatchesForProfile(graph *sbgraph.Graph, profile string) []reachMatch {
	seenProfiles := make(map[string]struct{})
	matches := reachMatchesForProfileRecursive(graph, profile, seenProfiles)
	return sortAndCompactReachMatches(matches)
}

func iokitReachMatchesForProfile(graph *sbgraph.Graph, profile string) []reachMatch {
	seenProfiles := make(map[string]struct{})
	matches := iokitReachMatchesForProfileRecursive(graph, profile, seenProfiles)
	return sortAndCompactReachMatches(matches)
}

func sortAndCompactReachMatches(matches []reachMatch) []reachMatch {
	sort.Slice(matches, func(i, j int) bool {
		iOp, jOp := reachMatchOperation(matches[i]), reachMatchOperation(matches[j])
		if iOp != jOp {
			return iOp < jOp
		}
		iTarget, jTarget := reachMatchTarget(matches[i]), reachMatchTarget(matches[j])
		if iTarget != jTarget {
			return iTarget < jTarget
		}
		return matches[i].GateCondition < matches[j].GateCondition
	})
	return compactReachMatches(matches)
}

func reachMatchOperation(match reachMatch) string {
	if match.Operation != "" {
		return match.Operation
	}
	if match.MachName != "" {
		return "mach-lookup"
	}
	return ""
}

func reachMatchTarget(match reachMatch) string {
	if match.Target != "" {
		return match.Target
	}
	return match.MachName
}

func reachMatchesForProfileRecursive(graph *sbgraph.Graph, profile string, seenProfiles map[string]struct{}) []reachMatch {
	if graph == nil || profile == "" {
		return nil
	}
	if _, seen := seenProfiles[profile]; seen {
		return nil
	}
	seenProfiles[profile] = struct{}{}
	defer delete(seenProfiles, profile)

	state := directReachMatchesForProfile(graph, profile)
	out := append([]reachMatch(nil), state.matches...)
	if !state.hasDefer {
		return out
	}

	parent := graphProfileParent(graph, profile)
	if parent == "" {
		return out
	}
	for _, match := range reachMatchesForProfileRecursive(graph, parent, seenProfiles) {
		if state.denyWildcard {
			continue
		}
		if _, denied := state.deniedMachNames[match.MachName]; denied {
			continue
		}
		out = append(out, match)
	}
	return compactReachMatches(out)
}

func directReachMatchesForProfile(graph *sbgraph.Graph, profile string) directReachState {
	state := directReachState{deniedMachNames: make(map[string]struct{})}
	if graph == nil {
		return state
	}
	for _, node := range graph.Nodes() {
		if node.Kind != sbgraph.NodeOperation || node.Profile != profile || node.Name != "mach-lookup" {
			continue
		}
		for _, edge := range graph.Outgoing(node.ID, sbgraph.EdgeAllows, sbgraph.EdgeDenies) {
			decision, ok := graph.Node(edge.Target)
			if !ok || decision == nil || decision.Kind != sbgraph.NodeDecision {
				continue
			}
			guard := graph.GuardExpr(decision.ID)
			switch decision.Decision {
			case "allow":
				state.matches = append(state.matches, reachMatchesForDecision(guard)...)
			case "deny":
				names := machNamesForGuard(guard)
				if len(names) == 0 {
					state.denyWildcard = true
					continue
				}
				for _, name := range names {
					state.deniedMachNames[name] = struct{}{}
				}
			case "defer-to-parent":
				state.hasDefer = true
			}
		}
	}
	state.matches = compactReachMatches(state.matches)
	return state
}

func iokitReachMatchesForProfileRecursive(graph *sbgraph.Graph, profile string, seenProfiles map[string]struct{}) []reachMatch {
	if graph == nil || profile == "" {
		return nil
	}
	if _, seen := seenProfiles[profile]; seen {
		return nil
	}
	seenProfiles[profile] = struct{}{}
	defer delete(seenProfiles, profile)

	state := directIOKitReachMatchesForProfile(graph, profile)
	out := append([]reachMatch(nil), state.matches...)
	if !state.hasDefer {
		return out
	}

	parent := graphProfileParent(graph, profile)
	if parent == "" {
		return out
	}
	for _, match := range iokitReachMatchesForProfileRecursive(graph, parent, seenProfiles) {
		if state.denyWildcard {
			continue
		}
		if _, denied := state.deniedTargets[reachMatchTarget(match)]; denied {
			continue
		}
		out = append(out, match)
	}
	return compactReachMatches(out)
}

type directIOKitReachState struct {
	matches       []reachMatch
	deniedTargets map[string]struct{}
	denyWildcard  bool
	hasDefer      bool
}

func directIOKitReachMatchesForProfile(graph *sbgraph.Graph, profile string) directIOKitReachState {
	state := directIOKitReachState{deniedTargets: make(map[string]struct{})}
	if graph == nil {
		return state
	}
	for _, node := range graph.Nodes() {
		operation := reachOperationName(node)
		if node.Kind != sbgraph.NodeOperation || node.Profile != profile || !strings.HasPrefix(operation, "iokit-open") {
			continue
		}
		for _, edge := range graph.Outgoing(node.ID, sbgraph.EdgeAllows, sbgraph.EdgeDenies) {
			decision, ok := graph.Node(edge.Target)
			if !ok || decision == nil || decision.Kind != sbgraph.NodeDecision {
				continue
			}
			guard := graph.GuardExpr(decision.ID)
			switch decision.Decision {
			case "allow":
				state.matches = append(state.matches, iokitReachMatchesForDecision(operation, guard)...)
			case "deny":
				targets := iokitTargetsForGuard(guard)
				if len(targets) == 0 {
					state.denyWildcard = true
					continue
				}
				for _, target := range targets {
					state.deniedTargets[target] = struct{}{}
				}
			case "defer-to-parent":
				state.hasDefer = true
			}
		}
	}
	state.matches = compactReachMatches(state.matches)
	return state
}

func iokitReachMatchesForDecision(operation string, guard *sbgraph.GuardExpr) []reachMatch {
	targets := iokitTargetsForGuard(guard)
	if len(targets) == 0 {
		targets = []string{"*"}
	}
	matches := make([]reachMatch, 0, len(targets))
	for _, target := range targets {
		gate, ok := residualGateForIOKitTarget(guard, target)
		if !ok {
			continue
		}
		matches = append(matches, reachMatch{Operation: operation, Target: target, GateCondition: gate})
	}
	return matches
}

func reachOperationName(node *sbgraph.Node) string {
	if node == nil {
		return ""
	}
	if node.Operation != "" {
		return node.Operation
	}
	return node.Name
}

func reachMatchesForDecision(guard *sbgraph.GuardExpr) []reachMatch {
	names := machNamesForGuard(guard)
	if len(names) == 0 {
		names = []string{"*"}
	}
	matches := make([]reachMatch, 0, len(names))
	for _, name := range names {
		gate, ok := residualGateForMachName(guard, name)
		if !ok {
			continue
		}
		matches = append(matches, reachMatch{MachName: name, GateCondition: gate})
	}
	return matches
}

func compactReachMatches(matches []reachMatch) []reachMatch {
	if len(matches) == 0 {
		return nil
	}
	out := matches[:0]
	seen := make(map[reachMatch]struct{}, len(matches))
	for _, match := range matches {
		if _, ok := seen[match]; ok {
			continue
		}
		seen[match] = struct{}{}
		out = append(out, match)
	}
	return out
}

func graphProfileParent(graph *sbgraph.Graph, profile string) string {
	if graph == nil {
		return ""
	}
	for _, node := range graph.Nodes() {
		if node.Kind == sbgraph.NodeProfile && node.Name == profile {
			return node.Metadata["parent"]
		}
	}
	return ""
}

func machNamesForGuard(guard *sbgraph.GuardExpr) []string {
	var names []string
	walkGuard(guard, func(node *sbgraph.GuardExpr) {
		if node.Kind != sbgraph.GuardExprKindPredicate || node.Name != "global-name" || node.Negated {
			return
		}
		name := strings.Trim(strings.TrimSpace(node.Value), "\"")
		if name != "" {
			names = append(names, name)
		}
	})
	sort.Strings(names)
	return compactStrings(names)
}

func iokitTargetsForGuard(guard *sbgraph.GuardExpr) []string {
	var names []string
	walkGuard(guard, func(node *sbgraph.GuardExpr) {
		if !isPositiveIOKitTargetPredicate(node) {
			return
		}
		name := strings.Trim(strings.TrimSpace(node.Value), "\"")
		if name != "" {
			names = append(names, name)
		}
	})
	sort.Strings(names)
	return compactStrings(names)
}

func residualGateForMachName(guard *sbgraph.GuardExpr, machName string) (string, bool) {
	residual, ok := residualGuardForMachName(guard, machName)
	if !ok {
		return "", false
	}
	gate := sbgraph.RenderGuardExpr(residual)
	if gate == "" {
		gate = "unconditional"
	}
	return gate, true
}

func residualGateForIOKitTarget(guard *sbgraph.GuardExpr, target string) (string, bool) {
	residual, ok := residualGuardForIOKitTarget(guard, target)
	if !ok {
		return "", false
	}
	gate := sbgraph.RenderGuardExpr(residual)
	if gate == "" {
		gate = "unconditional"
	}
	return gate, true
}

func residualGuardForMachName(guard *sbgraph.GuardExpr, machName string) (*sbgraph.GuardExpr, bool) {
	if guard == nil {
		return nil, true
	}
	switch guard.Kind {
	case sbgraph.GuardExprKindPredicate:
		if guard.Name == "global-name" && !guard.Negated && machName != "*" {
			if strings.Trim(strings.TrimSpace(guard.Value), "\"") == machName {
				return nil, true
			}
			return nil, false
		}
		return cloneGuard(guard), true
	case sbgraph.GuardExprKindGroup:
		return residualGroupForMachName(guard, machName)
	default:
		return cloneGuard(guard), true
	}
}

func residualGuardForIOKitTarget(guard *sbgraph.GuardExpr, target string) (*sbgraph.GuardExpr, bool) {
	if guard == nil {
		return nil, true
	}
	switch guard.Kind {
	case sbgraph.GuardExprKindPredicate:
		if isPositiveIOKitTargetPredicate(guard) && target != "*" {
			if strings.Trim(strings.TrimSpace(guard.Value), "\"") == target {
				return nil, true
			}
			return nil, false
		}
		return cloneGuard(guard), true
	case sbgraph.GuardExprKindGroup:
		return residualGroupForIOKitTarget(guard, target)
	default:
		return cloneGuard(guard), true
	}
}

func residualGroupForIOKitTarget(guard *sbgraph.GuardExpr, target string) (*sbgraph.GuardExpr, bool) {
	var children []sbgraph.GuardExpr
	switch guard.Operator {
	case "require-any":
		for _, child := range guard.Children {
			residual, ok := residualGuardForIOKitTarget(&child, target)
			if !ok {
				continue
			}
			if residual == nil {
				return nil, true
			}
			children = append(children, *residual)
		}
		if len(children) == 0 {
			return nil, false
		}
	default:
		for _, child := range guard.Children {
			residual, ok := residualGuardForIOKitTarget(&child, target)
			if !ok {
				return nil, false
			}
			if residual != nil {
				children = append(children, *residual)
			}
		}
	}
	if len(children) == 0 {
		return nil, true
	}
	if len(children) == 1 {
		return &children[0], true
	}
	cloned := cloneGuard(guard)
	cloned.Children = children
	return cloned, true
}

func isPositiveIOKitTargetPredicate(guard *sbgraph.GuardExpr) bool {
	if guard == nil || guard.Kind != sbgraph.GuardExprKindPredicate || guard.Negated {
		return false
	}
	switch guard.Name {
	case "iokit-registry-entry-class", "iokit-user-client-class", "iokit-connection":
		return true
	default:
		return false
	}
}

func residualGroupForMachName(guard *sbgraph.GuardExpr, machName string) (*sbgraph.GuardExpr, bool) {
	var children []sbgraph.GuardExpr
	switch guard.Operator {
	case "require-any":
		for _, child := range guard.Children {
			residual, ok := residualGuardForMachName(&child, machName)
			if !ok {
				continue
			}
			if residual == nil {
				return nil, true
			}
			children = append(children, *residual)
		}
		if len(children) == 0 {
			return nil, false
		}
	default:
		for _, child := range guard.Children {
			residual, ok := residualGuardForMachName(&child, machName)
			if !ok {
				return nil, false
			}
			if residual != nil {
				children = append(children, *residual)
			}
		}
	}
	if len(children) == 0 {
		return nil, true
	}
	if len(children) == 1 {
		return &children[0], true
	}
	cloned := cloneGuard(guard)
	cloned.Children = children
	return cloned, true
}

func cloneGuard(guard *sbgraph.GuardExpr) *sbgraph.GuardExpr {
	if guard == nil {
		return nil
	}
	cloned := *guard
	if guard.Children != nil {
		cloned.Children = append([]sbgraph.GuardExpr(nil), guard.Children...)
	}
	return &cloned
}

func walkGuard(guard *sbgraph.GuardExpr, visit func(*sbgraph.GuardExpr)) {
	if guard == nil || visit == nil {
		return
	}
	visit(guard)
	for idx := range guard.Children {
		walkGuard(&guard.Children[idx], visit)
	}
}

func loadLaunchdJoinRecords(cmd *cobra.Command) ([]launchd.Record, error) {
	jsonlPath, _ := cmd.Flags().GetString("launchd-jsonl")
	ipswPath, _ := cmd.Flags().GetString("ipsw")
	switch {
	case strings.TrimSpace(jsonlPath) != "":
		return readLaunchdJSONL(expandUserPath(jsonlPath))
	case strings.TrimSpace(ipswPath) != "":
		records, skipped, err := launchd.WalkIPSW(expandUserPath(ipswPath), &launchd.IPSWConfig{
			PemDB: mustFlagString(cmd, "pem-db"),
		})
		for _, skip := range skipped {
			log.Warnf("skipped %s volume: %v", skip.Volume, skip.Err)
		}
		return records, err
	default:
		return nil, fmt.Errorf("--join-launchd requires --launchd-jsonl or --ipsw")
	}
}

func readLaunchdJSONL(path string) ([]launchd.Record, error) {
	f, err := os.Open(filepath.Clean(path))
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var records []launchd.Record
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 64*1024), 16*1024*1024)
	for scanner.Scan() {
		line := bytes.TrimSpace(scanner.Bytes())
		if len(line) == 0 {
			continue
		}
		var record launchd.Record
		if err := json.Unmarshal(line, &record); err != nil {
			return nil, fmt.Errorf("%s: decode launchd JSONL: %w", path, err)
		}
		records = append(records, record)
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return records, nil
}

type iokitBundleJoiner struct {
	byClass map[string]map[string]struct{}
}

type iokitBundleJSONLRecord struct {
	Kind             string `json:"kind"`
	Class            string `json:"class"`
	Bundle           string `json:"bundle"`
	ServiceClass     string `json:"service_class"`
	ServiceBundle    string `json:"service_bundle"`
	UserClientClass  string `json:"user_client_class"`
	UserClientBundle string `json:"user_client_bundle"`
}

func loadIOKitBundleJoiner(cmd *cobra.Command, kernelArgs []string) (*iokitBundleJoiner, error) {
	jsonlPath, _ := cmd.Flags().GetString("iokit-methods-jsonl")
	if strings.TrimSpace(jsonlPath) != "" {
		return iokitBundleJoinerFromJSONL(expandUserPath(jsonlPath))
	}
	if len(kernelArgs) == 0 {
		return nil, nil
	}
	return iokitBundleJoinerFromKernelcache(filepath.Clean(kernelArgs[0]))
}

func iokitBundleJoinerFromKernelcache(kernelPath string) (*iokitBundleJoiner, error) {
	kernel, err := macho.Open(kernelPath)
	if err != nil {
		return nil, fmt.Errorf("open kernelcache for iokit bundle join: %w", err)
	}
	defer kernel.Close()

	records, err := iokit.Scan(kernel, iokit.Config{Kernelcache: kernelPath, Stderr: os.Stderr})
	if err != nil {
		return nil, fmt.Errorf("scan iokit methods for bundle join: %w", err)
	}
	joiner := newIOKitBundleJoiner()
	for _, record := range records {
		joiner.addRecord(record)
	}
	return joiner, nil
}

func iokitBundleJoinerFromJSONL(path string) (*iokitBundleJoiner, error) {
	f, err := os.Open(filepath.Clean(path))
	if err != nil {
		return nil, err
	}
	defer f.Close()

	joiner := newIOKitBundleJoiner()
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 64*1024), 16*1024*1024)
	for scanner.Scan() {
		line := bytes.TrimSpace(scanner.Bytes())
		if len(line) == 0 {
			continue
		}
		var record iokitBundleJSONLRecord
		if err := json.Unmarshal(line, &record); err != nil {
			return nil, fmt.Errorf("%s: decode iokit-methods JSONL: %w", path, err)
		}
		joiner.addJSONLRecord(record)
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return joiner, nil
}

func newIOKitBundleJoiner() *iokitBundleJoiner {
	return &iokitBundleJoiner{byClass: make(map[string]map[string]struct{})}
}

func (j *iokitBundleJoiner) addRecord(record iokit.Record) {
	switch record.Kind {
	case iokit.KindMethod:
		j.add(record.Class, record.Bundle)
	case iokit.KindServiceClient:
		j.add(record.UserClientClass, record.UserClientBundle)
		j.add(record.ServiceClass, record.ServiceBundle)
	}
}

func (j *iokitBundleJoiner) addJSONLRecord(record iokitBundleJSONLRecord) {
	switch record.Kind {
	case iokit.KindMethod:
		j.add(record.Class, record.Bundle)
	case iokit.KindServiceClient:
		j.add(record.UserClientClass, record.UserClientBundle)
		j.add(record.ServiceClass, record.ServiceBundle)
	}
}

func (j *iokitBundleJoiner) add(className, bundle string) {
	className = strings.TrimSpace(className)
	bundle = strings.TrimSpace(bundle)
	if j == nil || className == "" || bundle == "" {
		return
	}
	bundles := j.byClass[className]
	if bundles == nil {
		bundles = make(map[string]struct{})
		j.byClass[className] = bundles
	}
	bundles[bundle] = struct{}{}
}

func (j *iokitBundleJoiner) lookup(className string) string {
	if j == nil || strings.TrimSpace(className) == "" {
		return ""
	}
	bundles := j.byClass[className]
	if len(bundles) == 0 {
		return ""
	}
	out := make([]string, 0, len(bundles))
	for bundle := range bundles {
		out = append(out, bundle)
	}
	sort.Strings(out)
	return strings.Join(out, ";")
}

func reachRows(matches []reachMatch, launchdRows []launchd.Record, entitlements *entitlementJoiner, iokitBundles *iokitBundleJoiner, joinLaunchd, joinSB bool) []reachRow {
	launchdByMach := indexLaunchdByMachName(launchdRows)
	allLaunchd := launchdRecordsWithMachServices(launchdRows)
	var rows []reachRow
	for _, match := range matches {
		if reachMatchOperation(match) != "mach-lookup" {
			rows = append(rows, reachRow{
				Operation:     match.Operation,
				Target:        match.Target,
				GateCondition: match.GateCondition,
				KextBundle:    iokitBundles.lookup(match.Target),
			})
			continue
		}
		daemons := launchdByMach[match.MachName]
		if match.MachName == "*" && joinLaunchd {
			daemons = allLaunchd
		}
		if !joinLaunchd || len(daemons) == 0 {
			rows = append(rows, reachRow{
				Operation:     match.Operation,
				Target:        match.Target,
				MachName:      match.MachName,
				GateCondition: match.GateCondition,
			})
			continue
		}
		for _, daemon := range daemons {
			path := daemonExecutablePath(daemon)
			row := reachRow{
				Operation:     match.Operation,
				Target:        match.Target,
				MachName:      match.MachName,
				GateCondition: match.GateCondition,
				DaemonPath:    path,
			}
			if joinSB {
				row.DaemonSandboxProfile = daemon.SandboxProfile
			}
			if entitlements != nil && path != "" {
				row.DaemonEntitlements, row.HardenedProcess = entitlements.lookup(path)
			}
			rows = append(rows, row)
		}
	}
	sort.Slice(rows, func(i, j int) bool {
		iOp, jOp := reachRowOperation(rows[i]), reachRowOperation(rows[j])
		if iOp != jOp {
			return iOp < jOp
		}
		iTarget, jTarget := reachRowTarget(rows[i]), reachRowTarget(rows[j])
		if iTarget != jTarget {
			return iTarget < jTarget
		}
		if rows[i].DaemonPath != rows[j].DaemonPath {
			return rows[i].DaemonPath < rows[j].DaemonPath
		}
		return rows[i].GateCondition < rows[j].GateCondition
	})
	return compactReachRows(rows)
}

func reachRowOperation(row reachRow) string {
	if row.Operation != "" {
		return row.Operation
	}
	if row.MachName != "" {
		return "mach-lookup"
	}
	return ""
}

func reachRowTarget(row reachRow) string {
	if row.Target != "" {
		return row.Target
	}
	return row.MachName
}

func indexLaunchdByMachName(records []launchd.Record) map[string][]launchd.Record {
	out := make(map[string][]launchd.Record)
	for _, record := range records {
		for _, machName := range record.MachServices {
			if strings.TrimSpace(machName) == "" {
				continue
			}
			out[machName] = append(out[machName], record)
		}
	}
	for machName := range out {
		sort.Slice(out[machName], func(i, j int) bool {
			return daemonExecutablePath(out[machName][i]) < daemonExecutablePath(out[machName][j])
		})
	}
	return out
}

func launchdRecordsWithMachServices(records []launchd.Record) []launchd.Record {
	var out []launchd.Record
	for _, record := range records {
		if len(record.MachServices) > 0 {
			out = append(out, record)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		return daemonExecutablePath(out[i]) < daemonExecutablePath(out[j])
	})
	return out
}

func daemonExecutablePath(record launchd.Record) string {
	program := filepath.ToSlash(filepath.Clean(record.Program))
	if strings.HasPrefix(program, "/") {
		return program
	}
	if program == "." || program == "" {
		return ""
	}

	plistPath := filepath.ToSlash(filepath.Clean(record.PlistPath))
	if idx := strings.Index(plistPath, ".xpc/"); idx >= 0 {
		return filepath.ToSlash(filepath.Clean(plistPath[:idx+len(".xpc")] + "/" + program))
	}
	if idx := strings.Index(plistPath, ".app/"); idx >= 0 {
		return filepath.ToSlash(filepath.Clean(plistPath[:idx+len(".app")] + "/" + program))
	}
	return filepath.ToSlash(filepath.Clean(filepath.ToSlash(filepath.Dir(plistPath)) + "/" + program))
}

func compactReachRows(rows []reachRow) []reachRow {
	if len(rows) == 0 {
		return nil
	}
	out := rows[:0]
	seen := make(map[reachRow]struct{}, len(rows))
	for _, row := range rows {
		if _, ok := seen[row]; ok {
			continue
		}
		seen[row] = struct{}{}
		out = append(out, row)
	}
	return out
}

func writeReachTSV(f *os.File, rows []reachRow) error {
	fmt.Fprintln(f, "mach-name\tgate-condition\tdaemon-path\tdaemon-ents-json\tdaemon-sb-profile\thardened-process?")
	for _, row := range rows {
		fmt.Fprintf(f, "%s\t%s\t%s\t%s\t%s\t%s\n",
			tsvField(row.MachName),
			tsvField(row.GateCondition),
			tsvField(row.DaemonPath),
			tsvField(row.DaemonEntitlements),
			tsvField(row.DaemonSandboxProfile),
			tsvField(row.HardenedProcess),
		)
	}
	return nil
}

func writeReachExtendedTSV(f *os.File, rows []reachRow) error {
	fmt.Fprintln(f, "operation\ttarget\tkext-bundle\tmach-name\tgate-condition\tdaemon-path\tdaemon-ents-json\tdaemon-sb-profile\thardened-process?")
	for _, row := range rows {
		fmt.Fprintf(f, "%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n",
			tsvField(reachRowOperation(row)),
			tsvField(reachRowTarget(row)),
			tsvField(row.KextBundle),
			tsvField(row.MachName),
			tsvField(row.GateCondition),
			tsvField(row.DaemonPath),
			tsvField(row.DaemonEntitlements),
			tsvField(row.DaemonSandboxProfile),
			tsvField(row.HardenedProcess),
		)
	}
	return nil
}

func writeReachJSONL(f *os.File, rows []reachRow) error {
	enc := json.NewEncoder(f)
	enc.SetEscapeHTML(false)
	for _, row := range rows {
		if err := enc.Encode(row); err != nil {
			return err
		}
	}
	return nil
}

func tsvField(value string) string {
	replacer := strings.NewReplacer("\t", " ", "\r", " ", "\n", " ")
	return replacer.Replace(value)
}

type entitlementJoiner struct {
	root  string
	cache map[string]entitlementResult
}

type entitlementResult struct {
	json            string
	hardenedProcess string
}

func newEntitlementJoiner(root string) *entitlementJoiner {
	return &entitlementJoiner{
		root:  utils.MountedFilesystemRoot(expandUserPath(root)),
		cache: make(map[string]entitlementResult),
	}
}

func loadEntitlementJoiner(cmd *cobra.Command, matches []reachMatch, launchdRows []launchd.Record) (*entitlementJoiner, error) {
	fsRoot, _ := cmd.Flags().GetString("fs-root")
	if strings.TrimSpace(fsRoot) != "" {
		return newEntitlementJoiner(fsRoot), nil
	}

	ipswPath, _ := cmd.Flags().GetString("ipsw")
	if strings.TrimSpace(ipswPath) == "" {
		return nil, fmt.Errorf("--join-ent requires --fs-root or --ipsw")
	}

	wanted := daemonPathsForReach(matches, launchdRows)
	cache, err := entitlementResultsFromIPSW(expandUserPath(ipswPath), mustFlagString(cmd, "pem-db"), wanted)
	if err != nil {
		return nil, err
	}
	return &entitlementJoiner{
		cache: cache,
	}, nil
}

func (e *entitlementJoiner) lookup(daemonPath string) (string, string) {
	if e == nil {
		return "", ""
	}
	if result, ok := e.cache[daemonPath]; ok {
		return result.json, result.hardenedProcess
	}
	if strings.TrimSpace(e.root) == "" {
		return "", ""
	}
	result := e.read(daemonPath)
	e.cache[daemonPath] = result
	return result.json, result.hardenedProcess
}

func (e *entitlementJoiner) read(daemonPath string) entitlementResult {
	path := filepath.Join(e.root, filepath.FromSlash(strings.TrimPrefix(daemonPath, "/")))
	m, closeFn, err := openMachOForEntitlements(path)
	if err != nil {
		return entitlementResult{}
	}
	defer closeFn()

	doc, err := machoEntitlementMap(m)
	if err != nil {
		return entitlementResult{}
	}
	return entitlementResultFromMap(doc)
}

func entitlementResultsFromIPSW(ipswPath, pemDB string, wanted []string) (map[string]entitlementResult, error) {
	wantedSet := make(map[string]struct{}, len(wanted))
	for _, path := range wanted {
		if strings.TrimSpace(path) != "" {
			wantedSet[filepath.ToSlash(filepath.Clean(path))] = struct{}{}
		}
	}
	results := make(map[string]entitlementResult)
	if len(wantedSet) == 0 {
		return results, nil
	}

	err := search.ForEachMachoInIPSW(ipswPath, pemDB, func(path string, m *macho.File) error {
		normalized := filepath.ToSlash(filepath.Clean(path))
		if _, ok := wantedSet[normalized]; !ok {
			return nil
		}
		doc, err := machoEntitlementMap(m)
		if err != nil {
			return nil
		}
		results[normalized] = entitlementResultFromMap(doc)
		return nil
	})
	if err != nil {
		return nil, err
	}
	return results, nil
}

func daemonPathsForReach(matches []reachMatch, launchdRows []launchd.Record) []string {
	launchdByMach := indexLaunchdByMachName(launchdRows)
	allLaunchd := launchdRecordsWithMachServices(launchdRows)
	var paths []string
	for _, match := range matches {
		if reachMatchOperation(match) != "mach-lookup" {
			continue
		}
		daemons := launchdByMach[match.MachName]
		if match.MachName == "*" {
			daemons = allLaunchd
		}
		for _, daemon := range daemons {
			if path := daemonExecutablePath(daemon); path != "" {
				paths = append(paths, path)
			}
		}
	}
	sort.Strings(paths)
	return compactStrings(paths)
}

func entitlementResultFromMap(doc map[string]any) entitlementResult {
	data, err := json.Marshal(doc)
	if err != nil {
		return entitlementResult{}
	}
	return entitlementResult{
		json:            string(data),
		hardenedProcess: strconv.FormatBool(isHardenedProcess(doc)),
	}
}

func openMachOForEntitlements(path string) (*macho.File, func(), error) {
	fat, err := macho.OpenFat(filepath.Clean(path))
	if err == nil {
		if len(fat.Arches) == 0 {
			fat.Close()
			return nil, func() {}, fmt.Errorf("fat Mach-O has no arches: %s", path)
		}
		return fat.Arches[len(fat.Arches)-1].File, func() { fat.Close() }, nil
	}
	if !errors.Is(err, macho.ErrNotFat) {
		return nil, func() {}, err
	}
	m, err := macho.Open(filepath.Clean(path))
	if err != nil {
		return nil, func() {}, err
	}
	return m, func() { m.Close() }, nil
}

func machoEntitlementMap(m *macho.File) (map[string]any, error) {
	if m == nil || m.CodeSignature() == nil {
		return map[string]any{}, nil
	}
	payload := m.CodeSignature().Entitlements
	if payload == "" && len(m.CodeSignature().EntitlementsDER) > 0 {
		decoded, err := ents.DerDecode(m.CodeSignature().EntitlementsDER)
		if err != nil {
			return nil, err
		}
		payload = decoded
	}
	if strings.TrimSpace(payload) == "" {
		return map[string]any{}, nil
	}
	var doc map[string]any
	if err := plist.NewDecoder(strings.NewReader(payload)).Decode(&doc); err != nil {
		return nil, err
	}
	if doc == nil {
		return map[string]any{}, nil
	}
	return doc, nil
}

func isHardenedProcess(doc map[string]any) bool {
	return entitlementTruthy(doc["com.apple.developer.hardened-process"]) ||
		entitlementTruthy(doc["com.apple.security.hardened-process"])
}

func entitlementTruthy(value any) bool {
	switch v := value.(type) {
	case bool:
		return v
	case string:
		parsed, err := strconv.ParseBool(v)
		return err == nil && parsed
	default:
		return false
	}
}

func compactStrings(values []string) []string {
	if len(values) == 0 {
		return nil
	}
	out := values[:0]
	var last string
	for idx, value := range values {
		if idx > 0 && value == last {
			continue
		}
		out = append(out, value)
		last = value
	}
	return out
}

func mustFlagString(cmd *cobra.Command, name string) string {
	value, err := cmd.Flags().GetString(name)
	if err != nil {
		return ""
	}
	return value
}

func expandUserPath(path string) string {
	if path == "~" {
		home, err := os.UserHomeDir()
		if err != nil {
			return path
		}
		return home
	}
	if after, ok := strings.CutPrefix(path, "~/"); ok {
		home, err := os.UserHomeDir()
		if err != nil {
			return path
		}
		return filepath.Join(home, after)
	}
	return path
}
