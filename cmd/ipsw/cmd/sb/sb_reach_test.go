//go:build sandbox

package sb

import (
	"strings"
	"testing"

	"github.com/blacktop/ipsw/pkg/launchd"
	sbgraph "github.com/blacktop/ipsw/pkg/sandbox/graph"
)

func TestReachMatchesKeepResidualGateCondition(t *testing.T) {
	graph := sbgraph.New()
	graph.AddNode(&sbgraph.Node{ID: "profile:web", Kind: sbgraph.NodeProfile, Name: "web", Profile: "web"})
	graph.AddNode(&sbgraph.Node{ID: "op:web:mach-lookup", Kind: sbgraph.NodeOperation, Name: "mach-lookup", Profile: "web", Operation: "mach-lookup"})
	graph.AddNode(&sbgraph.Node{ID: "decision:web:allow", Kind: sbgraph.NodeDecision, Decision: "allow", Profile: "web", Operation: "mach-lookup"})
	graph.AddNode(&sbgraph.Node{ID: "pred:name", Kind: sbgraph.NodePredicate, Name: "global-name", Value: `"com.apple.mobilegestalt.xpc"`})
	graph.AddNode(&sbgraph.Node{ID: "pred:extension", Kind: sbgraph.NodePredicate, Name: "extension", Value: `"com.apple.webkit.extension.mach"`})
	graph.AddEdge(&sbgraph.Edge{Source: "profile:web", Target: "op:web:mach-lookup", Kind: sbgraph.EdgeContains})
	graph.AddEdge(&sbgraph.Edge{Source: "op:web:mach-lookup", Target: "decision:web:allow", Kind: sbgraph.EdgeAllows})
	graph.AddEdge(&sbgraph.Edge{Source: "decision:web:allow", Target: "pred:name", Kind: sbgraph.EdgeFilteredBy})
	graph.AddEdge(&sbgraph.Edge{Source: "decision:web:allow", Target: "pred:extension", Kind: sbgraph.EdgeFilteredBy})

	matches := reachMatchesForProfile(graph, "web")
	if len(matches) != 1 {
		t.Fatalf("matches=%#v, want one", matches)
	}
	if matches[0].MachName != "com.apple.mobilegestalt.xpc" {
		t.Fatalf("mach name=%q", matches[0].MachName)
	}
	if !strings.Contains(matches[0].GateCondition, "com.apple.webkit.extension.mach") {
		t.Fatalf("gate condition=%q, want extension gate", matches[0].GateCondition)
	}
	if strings.Contains(matches[0].GateCondition, "mobilegestalt") {
		t.Fatalf("gate condition still contains mach-name predicate: %q", matches[0].GateCondition)
	}
}

func TestReachMatchesKeepPerMachResidualGateCondition(t *testing.T) {
	graph := sbgraph.New()
	graph.AddNode(&sbgraph.Node{ID: "profile:web", Kind: sbgraph.NodeProfile, Name: "web", Profile: "web"})
	graph.AddNode(&sbgraph.Node{ID: "op:web:mach-lookup", Kind: sbgraph.NodeOperation, Name: "mach-lookup", Profile: "web", Operation: "mach-lookup"})
	graph.AddNode(&sbgraph.Node{ID: "decision:web:allow", Kind: sbgraph.NodeDecision, Decision: "allow", Profile: "web", Operation: "mach-lookup"})
	graph.AddNode(&sbgraph.Node{ID: "group:any", Kind: sbgraph.NodeGroup, Operator: "require-any"})
	graph.AddNode(&sbgraph.Node{ID: "group:a", Kind: sbgraph.NodeGroup, Operator: "require-all"})
	graph.AddNode(&sbgraph.Node{ID: "group:b", Kind: sbgraph.NodeGroup, Operator: "require-all"})
	graph.AddNode(&sbgraph.Node{ID: "pred:name:a", Kind: sbgraph.NodePredicate, Name: "global-name", Value: `"com.apple.a"`})
	graph.AddNode(&sbgraph.Node{ID: "pred:name:b", Kind: sbgraph.NodePredicate, Name: "global-name", Value: `"com.apple.b"`})
	graph.AddNode(&sbgraph.Node{ID: "pred:ext:a", Kind: sbgraph.NodePredicate, Name: "extension", Value: `"com.apple.extension.a"`})
	graph.AddNode(&sbgraph.Node{ID: "pred:ext:b", Kind: sbgraph.NodePredicate, Name: "extension", Value: `"com.apple.extension.b"`})
	graph.AddEdge(&sbgraph.Edge{Source: "profile:web", Target: "op:web:mach-lookup", Kind: sbgraph.EdgeContains})
	graph.AddEdge(&sbgraph.Edge{Source: "op:web:mach-lookup", Target: "decision:web:allow", Kind: sbgraph.EdgeAllows})
	graph.AddEdge(&sbgraph.Edge{Source: "decision:web:allow", Target: "group:any", Kind: sbgraph.EdgeHasChild})
	graph.AddEdge(&sbgraph.Edge{Source: "group:any", Target: "group:a", Kind: sbgraph.EdgeHasChild})
	graph.AddEdge(&sbgraph.Edge{Source: "group:any", Target: "group:b", Kind: sbgraph.EdgeHasChild})
	graph.AddEdge(&sbgraph.Edge{Source: "group:a", Target: "pred:name:a", Kind: sbgraph.EdgeHasChild})
	graph.AddEdge(&sbgraph.Edge{Source: "group:a", Target: "pred:ext:a", Kind: sbgraph.EdgeHasChild})
	graph.AddEdge(&sbgraph.Edge{Source: "group:b", Target: "pred:name:b", Kind: sbgraph.EdgeHasChild})
	graph.AddEdge(&sbgraph.Edge{Source: "group:b", Target: "pred:ext:b", Kind: sbgraph.EdgeHasChild})

	matches := reachMatchesForProfile(graph, "web")
	if len(matches) != 2 {
		t.Fatalf("matches=%#v, want two", matches)
	}

	gates := make(map[string]string)
	for _, match := range matches {
		gates[match.MachName] = match.GateCondition
	}
	if !strings.Contains(gates["com.apple.a"], "com.apple.extension.a") || strings.Contains(gates["com.apple.a"], "com.apple.extension.b") {
		t.Fatalf("wrong residual gate for com.apple.a: %q", gates["com.apple.a"])
	}
	if !strings.Contains(gates["com.apple.b"], "com.apple.extension.b") || strings.Contains(gates["com.apple.b"], "com.apple.extension.a") {
		t.Fatalf("wrong residual gate for com.apple.b: %q", gates["com.apple.b"])
	}
}

func TestIOKitReachMatchesKeepResidualGateCondition(t *testing.T) {
	graph := sbgraph.New()
	graph.AddNode(&sbgraph.Node{ID: "profile:web", Kind: sbgraph.NodeProfile, Name: "web", Profile: "web"})
	graph.AddNode(&sbgraph.Node{ID: "op:web:iokit", Kind: sbgraph.NodeOperation, Name: "iokit-open-user-client", Profile: "web", Operation: "iokit-open-user-client"})
	graph.AddNode(&sbgraph.Node{ID: "decision:web:allow", Kind: sbgraph.NodeDecision, Decision: "allow", Profile: "web", Operation: "iokit-open-user-client"})
	graph.AddNode(&sbgraph.Node{ID: "pred:class", Kind: sbgraph.NodePredicate, Name: "iokit-user-client-class", Value: `"IOSurfaceRootUserClient"`})
	graph.AddNode(&sbgraph.Node{ID: "pred:ent", Kind: sbgraph.NodePredicate, Name: "entitlement", Value: `"com.apple.private.iokit.test"`})
	graph.AddEdge(&sbgraph.Edge{Source: "profile:web", Target: "op:web:iokit", Kind: sbgraph.EdgeContains})
	graph.AddEdge(&sbgraph.Edge{Source: "op:web:iokit", Target: "decision:web:allow", Kind: sbgraph.EdgeAllows})
	graph.AddEdge(&sbgraph.Edge{Source: "decision:web:allow", Target: "pred:class", Kind: sbgraph.EdgeFilteredBy})
	graph.AddEdge(&sbgraph.Edge{Source: "decision:web:allow", Target: "pred:ent", Kind: sbgraph.EdgeFilteredBy})

	matches := iokitReachMatchesForProfile(graph, "web")
	if len(matches) != 1 {
		t.Fatalf("matches=%#v, want one", matches)
	}
	if matches[0].Operation != "iokit-open-user-client" || matches[0].Target != "IOSurfaceRootUserClient" {
		t.Fatalf("unexpected iokit match: %#v", matches[0])
	}
	if !strings.Contains(matches[0].GateCondition, "com.apple.private.iokit.test") {
		t.Fatalf("gate condition=%q, want entitlement gate", matches[0].GateCondition)
	}
	if strings.Contains(matches[0].GateCondition, "IOSurfaceRootUserClient") {
		t.Fatalf("gate condition still contains iokit target predicate: %q", matches[0].GateCondition)
	}
}

func TestReachRowsKeepIOKitRowsOutOfLaunchdJoin(t *testing.T) {
	matches := []reachMatch{{
		Operation:     "iokit-open-user-client",
		Target:        "IOSurfaceRootUserClient",
		GateCondition: "unconditional",
	}}
	records := []launchd.Record{{
		Program:      "/usr/libexec/testd",
		MachServices: []string{"IOSurfaceRootUserClient"},
	}}

	rows := reachRows(matches, records, nil, nil, true, true)
	if len(rows) != 1 {
		t.Fatalf("rows=%#v, want one", rows)
	}
	if rows[0].DaemonPath != "" {
		t.Fatalf("iokit row unexpectedly joined to launchd daemon: %#v", rows[0])
	}
	if rows[0].Operation != "iokit-open-user-client" || rows[0].Target != "IOSurfaceRootUserClient" {
		t.Fatalf("unexpected iokit row: %#v", rows[0])
	}
}

func TestReachRowsJoinIOKitKextBundle(t *testing.T) {
	matches := []reachMatch{{
		Operation:     "iokit-open-user-client",
		Target:        "IOSurfaceRootUserClient",
		GateCondition: "unconditional",
	}}
	bundles := newIOKitBundleJoiner()
	bundles.add("IOSurfaceRootUserClient", "com.apple.iokit.IOSurface")

	rows := reachRows(matches, nil, nil, bundles, false, false)
	if len(rows) != 1 {
		t.Fatalf("rows=%#v, want one", rows)
	}
	if rows[0].KextBundle != "com.apple.iokit.IOSurface" {
		t.Fatalf("kext bundle=%q, want IOSurface bundle", rows[0].KextBundle)
	}
}

func TestDaemonExecutablePathForXPCContentsLayout(t *testing.T) {
	record := launchd.Record{
		SourceKind: launchd.SourceKindXPCBundle,
		PlistPath:  "/System/Library/Frameworks/Foo.framework/XPCServices/Bar.xpc/Contents/Info.plist",
		Program:    "Contents/MacOS/Bar",
	}
	got := daemonExecutablePath(record)
	want := "/System/Library/Frameworks/Foo.framework/XPCServices/Bar.xpc/Contents/MacOS/Bar"
	if got != want {
		t.Fatalf("daemon path=%q, want %q", got, want)
	}
}

func TestReachRowsJoinLaunchdByMachName(t *testing.T) {
	matches := []reachMatch{{MachName: "com.apple.test.service", GateCondition: "unconditional"}}
	records := []launchd.Record{{
		PlistPath:      "/System/Library/LaunchDaemons/com.apple.test.plist",
		Program:        "/usr/libexec/testd",
		MachServices:   []string{"com.apple.test.service"},
		SandboxProfile: "testd",
	}}

	rows := reachRows(matches, records, nil, nil, true, true)
	if len(rows) != 1 {
		t.Fatalf("rows=%#v, want one", rows)
	}
	if rows[0].DaemonPath != "/usr/libexec/testd" || rows[0].DaemonSandboxProfile != "testd" {
		t.Fatalf("unexpected joined row: %#v", rows[0])
	}
}
