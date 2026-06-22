package crashlog

import (
	"bytes"
	"fmt"
	"sort"
	"strings"
	"text/tabwriter"

	"github.com/dustin/go-humanize"
)

// This file implements the JetsamEvent (bug_type 298) crash-log family: the
// data model, kill-cause table, and renderer. It registers itself with the
// report renderer registry, so supporting it needs no edits to a central switch.

func init() {
	registerIpsRenderer((*Ips).jetsamString, "Jetsam", "298")
}

// Jetsam is the payload of a JetsamEvent (bug_type 298) report. These are
// generated when the memory manager (jetsam) terminates one or more processes
// under memory pressure. Unlike crash/panic reports there are no backtraces to
// symbolicate; the report is a snapshot of every process and the device's
// memory state at the moment of the kill.
type Jetsam struct {
	Build            string             `json:"build,omitempty"`
	Product          string             `json:"product,omitempty"`
	Kernel           string             `json:"kernel,omitempty"`
	Incident         string             `json:"incident,omitempty"`
	CrashReporterKey string             `json:"crashReporterKey,omitempty"`
	Date             string             `json:"date,omitempty"`
	BugType          string             `json:"bug_type,omitempty"`
	TimeDelta        int                `json:"timeDelta,omitempty"`
	MemoryStatus     JetsamMemoryStatus `json:"memoryStatus"`
	LargestProcess   string             `json:"largestProcess,omitempty"`
	GenCounter       int                `json:"genCounter,omitempty"`
	Processes        []JetsamProcess    `json:"processes,omitempty"`
}

// JetsamMemoryStatus is the device-wide memory snapshot embedded in a 298 report.
type JetsamMemoryStatus struct {
	CompressorSize  int64  `json:"compressorSize,omitempty"`
	Compressions    int64  `json:"compressions,omitempty"`
	Decompressions  int64  `json:"decompressions,omitempty"`
	Uncompressed    int64  `json:"uncompressed,omitempty"`
	PageSize        int64  `json:"pageSize,omitempty"`
	ZoneMapCap      int64  `json:"zoneMapCap,omitempty"`
	ZoneMapSize     int64  `json:"zoneMapSize,omitempty"`
	LargestZone     string `json:"largestZone,omitempty"`
	LargestZoneSize int64  `json:"largestZoneSize,omitempty"`
	MemoryPages     struct {
		Active      int64 `json:"active,omitempty"`
		Anonymous   int64 `json:"anonymous,omitempty"`
		FileBacked  int64 `json:"fileBacked,omitempty"`
		Free        int64 `json:"free,omitempty"`
		Inactive    int64 `json:"inactive,omitempty"`
		Purgeable   int64 `json:"purgeable,omitempty"`
		Speculative int64 `json:"speculative,omitempty"`
		Throttled   int64 `json:"throttled,omitempty"`
		Wired       int64 `json:"wired,omitempty"`
	} `json:"memoryPages"`
}

// JetsamProcess is one process entry in a 298 report. The Reason field is only
// present on the process(es) jetsam actually terminated.
type JetsamProcess struct {
	PID           int      `json:"pid,omitempty"`
	Name          string   `json:"name,omitempty"`
	UUID          string   `json:"uuid,omitempty"`
	States        []string `json:"states,omitempty"`
	Priority      int      `json:"priority"`              // jetsam priority band (0 == idle, killed first)
	RPages        int      `json:"rpages,omitempty"`      // resident pages at time of report
	LifetimeMax   int      `json:"lifetimeMax,omitempty"` // high-water mark of resident pages
	Purgeable     int      `json:"purgeable,omitempty"`
	Reason        string   `json:"reason,omitempty"` // kill cause, only set on terminated processes
	KillDelta     int      `json:"killDelta,omitempty"`
	IdleDelta     int64    `json:"idleDelta,omitempty"`
	Age           int64    `json:"age,omitempty"`
	CPUTime       float64  `json:"cpuTime,omitempty"`
	FDs           int      `json:"fds,omitempty"`
	Coalition     int      `json:"coalition,omitempty"`
	CSFlags       int64    `json:"csFlags,omitempty"`
	CSTrustLevel  int      `json:"csTrustLevel,omitempty"`
	MemRegions    int      `json:"mem_regions,omitempty"`
	GenCount      int      `json:"genCount,omitempty"`
	FreezeSkip    string   `json:"freeze_skip_reason:,omitempty"` // trailing colon matches Apple's key
	PhysicalPages struct {
		Internal          []int `json:"internal,omitempty"`
		FrozenToSwapPages int   `json:"frozen_to_swap_pages,omitempty"`
	} `json:"physicalPages"`
}

// jetsamReasonExplain maps XNU memorystatus kill-cause strings to a short,
// human-readable explanation. Strings come from memstat_kill_cause_name[] in
// bsd/kern/kern_memorystatus.c.
var jetsamReasonExplain = map[string]string{
	"jettisoned":                   "generic jetsam kill",
	"highwater":                    "exceeded the memory high-water mark",
	"vnode-limit":                  "system hit the vnode limit",
	"vm-pageshortage":              "system-wide free page shortage",
	"proc-thrashing":               "process was thrashing",
	"fc-thrashing":                 "file-cache thrashing",
	"per-process-limit":            "exceeded its per-process memory limit",
	"disk-space-shortage":          "low disk space",
	"idle-exit":                    "idle process reaped",
	"long-idle-exit":               "long-idle process reaped",
	"zone-map-exhaustion":          "kernel zone map exhausted",
	"vm-compressor-thrashing":      "VM compressor thrashing",
	"vm-compressor-space-shortage": "VM compressor space shortage",
	"low-swap":                     "low swap space",
	"sustained-memory-pressure":    "sustained memory pressure",
	"vm-pageout-starvation":        "pageout thread starvation",
	"conclave-limit":               "exceeded its conclave memory limit",
	"diagnostic":                   "diagnostic kill",
}

// jetsamPages formats a page count as "N pages (humanized bytes)". Memory is
// reported in binary units (KiB/MiB/GiB) per the convention for RAM footprints.
func jetsamPages(pages int, pageSize int64) string {
	if pageSize <= 0 {
		pageSize = 16384
	}
	var nbytes uint64
	if pages > 0 { // guard a corrupt negative count from rendering as a 16 EiB figure
		nbytes = uint64(pages) * uint64(pageSize)
	}
	return fmt.Sprintf("%s pages (%s)", humanize.Comma(int64(pages)), humanize.IBytes(nbytes))
}

// iBytesNonNeg formats a signed byte count, clamping negatives to 0 so a corrupt
// field can't wrap through uint64 into an absurd ~16 EiB figure.
func iBytesNonNeg(n int64) string {
	if n < 0 {
		n = 0
	}
	return humanize.IBytes(uint64(n))
}

// jetsamNameMatches reports whether a process name from the report matches a
// --proc filter. Jetsam truncates names (comm), so an exact compare misses the
// full name a user knows; match a substring either direction.
func jetsamNameMatches(name, filter string) bool {
	name, filter = strings.ToLower(name), strings.ToLower(filter)
	return strings.Contains(name, filter) || strings.Contains(filter, name)
}

// jetsamString renders a JetsamEvent (bug_type 298) report: which process(es)
// jetsam terminated and why, the device-wide memory snapshot, and the biggest
// memory consumers at the time of the kill. There are no addresses to
// symbolicate, so this is a display-only pretty printer.
func (i *Ips) jetsamString() string {
	if i.Jetsam == nil {
		return colorError("malformed JetsamEvent: missing payload")
	}
	pageSize := i.Jetsam.MemoryStatus.PageSize
	if pageSize <= 0 {
		pageSize = 16384
	}

	osVersion := i.Jetsam.Build // payload build string, e.g. "iPhone OS 27.0 (24A5355q)"
	if osVersion == "" {
		osVersion = i.Header.OsVersion
	}
	var out strings.Builder
	out.WriteString(fmt.Sprintf("[%s] - %s - %s %s\n",
		colorTime(i.Header.Timestamp.Format("02Jan2006 15:04:05")),
		colorError(i.Header.BugTypeDesc),
		i.Jetsam.Product, osVersion))
	if i.Jetsam.Kernel != "" {
		out.WriteString(fmt.Sprintf("%s: %s\n", colorField("Kernel"), i.Jetsam.Kernel))
	}
	out.WriteString("\n")
	out.WriteString(i.jetsamKilledString(pageSize))
	out.WriteString(i.jetsamMemoryString(pageSize))
	out.WriteString(i.jetsamProcessesString(pageSize))
	return out.String()
}

// jetsamKilledString renders the process(es) jetsam terminated (those carrying a
// kill Reason), including a plain-English explanation of the kill cause.
func (i *Ips) jetsamKilledString(pageSize int64) string {
	var out strings.Builder
	for _, p := range i.Jetsam.Processes {
		if p.Reason == "" {
			continue
		}
		reason := p.Reason
		if explain, ok := jetsamReasonExplain[p.Reason]; ok {
			reason = fmt.Sprintf("%s (%s)", p.Reason, explain)
		}
		out.WriteString(fmt.Sprintf("%s: %s [%s]\n", colorField("Killed Process"), colorImage("%s", p.Name), colorBold("%d", p.PID)))
		buf := bytes.NewBufferString("")
		w := tabwriter.NewWriter(buf, 0, 0, 2, ' ', 0)
		fmt.Fprintf(w, "  %s\t%s\n", colorField("Reason"), colorError(reason))
		fmt.Fprintf(w, "  %s\t%s\n", colorField("Resident"), jetsamPages(p.RPages, pageSize))
		// physicalPages.internal is [resident, compressed]; the split explains how
		// much of the footprint was live vs already compressed when jetsam acted.
		if len(p.PhysicalPages.Internal) >= 2 {
			fmt.Fprintf(w, "  %s\t%s resident / %s compressed\n", colorField("Internal"),
				jetsamPages(p.PhysicalPages.Internal[0], pageSize),
				jetsamPages(p.PhysicalPages.Internal[1], pageSize))
		}
		if p.PhysicalPages.FrozenToSwapPages > 0 {
			fmt.Fprintf(w, "  %s\t%s\n", colorField("Frozen to Swap"), jetsamPages(p.PhysicalPages.FrozenToSwapPages, pageSize))
		}
		if p.LifetimeMax > 0 {
			fmt.Fprintf(w, "  %s\t%s\n", colorField("Lifetime Max"), jetsamPages(p.LifetimeMax, pageSize))
		}
		fmt.Fprintf(w, "  %s\t%d\n", colorField("Priority"), p.Priority)
		if len(p.States) > 0 {
			fmt.Fprintf(w, "  %s\t%s\n", colorField("States"), strings.Join(p.States, ", "))
		}
		if p.CPUTime > 0 {
			fmt.Fprintf(w, "  %s\t%.3fs\n", colorField("CPU Time"), p.CPUTime)
		}
		w.Flush()
		out.WriteString(buf.String() + "\n")
	}
	return out.String()
}

// jetsamMemoryString renders the device-wide memory snapshot from a 298 report.
func (i *Ips) jetsamMemoryString(pageSize int64) string {
	ms := i.Jetsam.MemoryStatus
	mp := ms.MemoryPages
	var out strings.Builder
	out.WriteString(colorField("Memory Status") + ":\n")
	buf := bytes.NewBufferString("")
	w := tabwriter.NewWriter(buf, 0, 0, 2, ' ', 0)
	fmt.Fprintf(w, "  %s\t%s\n", colorField("Page Size"), humanize.IBytes(uint64(pageSize)))
	fmt.Fprintf(w, "  %s\t%s\n", colorField("Free"), jetsamPages(int(mp.Free), pageSize))
	fmt.Fprintf(w, "  %s\t%s\n", colorField("Active"), jetsamPages(int(mp.Active), pageSize))
	fmt.Fprintf(w, "  %s\t%s\n", colorField("Inactive"), jetsamPages(int(mp.Inactive), pageSize))
	fmt.Fprintf(w, "  %s\t%s\n", colorField("Wired"), jetsamPages(int(mp.Wired), pageSize))
	if mp.Anonymous > 0 {
		fmt.Fprintf(w, "  %s\t%s\n", colorField("Anonymous"), jetsamPages(int(mp.Anonymous), pageSize))
	}
	fmt.Fprintf(w, "  %s\t%s\n", colorField("File-backed"), jetsamPages(int(mp.FileBacked), pageSize))
	fmt.Fprintf(w, "  %s\t%s\n", colorField("Purgeable"), jetsamPages(int(mp.Purgeable), pageSize))
	fmt.Fprintf(w, "  %s\t%s, %s uncompressed\n", colorField("Compressor"), jetsamPages(int(ms.CompressorSize), pageSize), jetsamPages(int(ms.Uncompressed), pageSize))
	if ms.LargestZone != "" {
		fmt.Fprintf(w, "  %s\t%s (%s)\n", colorField("Largest Zone"), ms.LargestZone, iBytesNonNeg(ms.LargestZoneSize))
	}
	if ms.ZoneMapSize > 0 {
		fmt.Fprintf(w, "  %s\t%s / %s cap\n", colorField("Zone Map"), iBytesNonNeg(ms.ZoneMapSize), iBytesNonNeg(ms.ZoneMapCap))
	}
	w.Flush()
	out.WriteString(buf.String() + "\n")
	return out.String()
}

// jetsamProcessesString renders the process snapshot sorted by resident memory.
// By default only the top consumers are shown; --all (or --proc) shows the full
// list, and --proc filters to a single process name.
func (i *Ips) jetsamProcessesString(pageSize int64) string {
	total := len(i.Jetsam.Processes)
	filter := ""
	if i.Config != nil {
		filter = i.Config.Process
	}
	procs := i.Jetsam.Processes
	if filter != "" {
		var filtered []JetsamProcess
		for _, p := range procs {
			if jetsamNameMatches(p.Name, filter) {
				filtered = append(filtered, p)
			}
		}
		procs = filtered
		if len(procs) == 0 {
			return fmt.Sprintf("%s: no process matching %q found in this report (%d total)\n", colorField("Processes"), filter, total)
		}
	}
	sorted := make([]JetsamProcess, len(procs))
	copy(sorted, procs)
	sort.Slice(sorted, func(a, b int) bool { return sorted[a].RPages > sorted[b].RPages })

	var header string
	limit := min(15, len(sorted))
	switch {
	case filter != "":
		header = fmt.Sprintf("%s %q (%d of %d):\n", colorField("Processes matching"), filter, len(sorted), total)
		limit = len(sorted)
	case i.Config != nil && i.Config.All:
		header = fmt.Sprintf("%s (%d total):\n", colorField("Processes"), total)
		limit = len(sorted)
	default:
		header = fmt.Sprintf("%s (%d total):\n", colorField("Top Memory Consumers"), total)
	}

	var out strings.Builder
	out.WriteString(header)
	buf := bytes.NewBufferString("")
	w := tabwriter.NewWriter(buf, 0, 0, 2, ' ', 0)
	for idx := 0; idx < limit; idx++ {
		p := sorted[idx]
		marker := ""
		if p.Reason != "" {
			marker = colorError(" (killed: " + p.Reason + ")")
		}
		fmt.Fprintf(w, "  %2d: %s\t[%s]\t%s\tprio=%d\t%s%s\n",
			idx+1,
			colorImage("%s", p.Name),
			colorBold("%d", p.PID),
			jetsamPages(p.RPages, pageSize),
			p.Priority,
			strings.Join(p.States, ","),
			marker)
	}
	w.Flush()
	out.WriteString(buf.String())
	if limit < len(sorted) {
		out.WriteString(fmt.Sprintf("  ... %d more (use --all to show every process)\n", len(sorted)-limit))
	}
	return out.String()
}

func init() {
	registerIpsRenderer((*Ips).panicString, "Panic", "210", "288")
	// 308 (ExcUserFault) shares the 309 crash payload shape and renderer.
	registerIpsRenderer((*Ips).crashString, "Crash", "308", "309")
}
