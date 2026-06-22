package crashlog

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"regexp"
	"strconv"
	"strings"
	"text/tabwriter"

	"github.com/blacktop/ipsw/pkg/dyld"
)

// Microstackshot is a sampled resource report in Apple's "Microstackshots" text
// format (Report Version 65): a JSON header line followed by a human-readable
// body. This covers the SymptomsIO disk-writes report (bug_type 145),
// SymptomsCPUUsage (202) and the other *_resource reports, which trip when a
// process exceeds a CPU/disk/wakeups budget. We surface the resource Event and
// the heaviest stack for the offending process.
type Microstackshot struct {
	Header        IpsMetadata
	Command       string
	Path          string
	PID           int
	OSVersion     string
	Architecture  string
	DataSource    string
	SharedCache   string // raw "Shared Cache:" value (UUID + slid base + slide)
	Event         string
	ActionTaken   string
	EventDetail   []string // the lines describing what limit was exceeded
	HardwareModel string
	MemorySize    string
	HeaviestStack []MicrostackFrame
	Config        *Config
}

// MicrostackFrame is one sampled frame: a weight (sample count), the (usually
// unsymbolicated "???") symbol, and the image + offset it resolves to.
type MicrostackFrame struct {
	Count  int
	Symbol string
	Image  string
	Offset uint64
	Addr   uint64
}

// frameRe matches a microstackshot frame, e.g.
//
//	61  ??? (libsystem_pthread.dylib + 2240) [0x22f72b8c0]
var frameRe = regexp.MustCompile(`^\s*(\d+)\s+(.+?)\s+\((.+?)\s+\+\s+(\d+)\)(?:\s+\[(0x[0-9a-fA-F]+)\])?\s*$`)

// OpenMicrostackshot parses a Microstackshots text report (bug_type 145/202/...).
func OpenMicrostackshot(in string, conf *Config) (*Microstackshot, error) {
	data, err := os.ReadFile(in)
	if err != nil {
		return nil, err
	}
	before, after, ok := bytes.Cut(data, []byte{'\n'})
	if !ok {
		return nil, fmt.Errorf("microstackshot %s: missing header line", in)
	}
	ms := &Microstackshot{Config: conf}
	if err := json.Unmarshal(before, &ms.Header); err != nil {
		return nil, fmt.Errorf("microstackshot %s: decode header: %w", in, err)
	}
	if db, err := GetLogTypes(); err == nil {
		if bt, ok := (*db)[ms.Header.BugType]; ok {
			ms.Header.BugTypeDesc = bt.Name
		}
	}
	ms.parseBody(after)
	return ms, nil
}

// parseBody walks the text body, capturing the preamble key/value fields, the
// resource Event block, and the heaviest-stack frames (stopping at the first
// per-process "Powerstats" section, which is out of scope).
func (ms *Microstackshot) parseBody(body []byte) {
	sc := bufio.NewScanner(bytes.NewReader(body))
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	inStack, inEvent := false, false
	for sc.Scan() {
		line := sc.Text()
		switch {
		case strings.HasPrefix(line, "Powerstats for:"):
			return // per-process sections are out of scope
		case strings.HasPrefix(line, "Heaviest stack for the target process:"):
			inStack, inEvent = true, false
		case inStack:
			if strings.TrimSpace(line) == "" {
				inStack = false
				continue
			}
			if f, ok := parseFrame(line); ok {
				ms.HeaviestStack = append(ms.HeaviestStack, f)
			}
		default:
			inEvent = ms.parseField(line, inEvent)
		}
	}
}

// parseField captures one preamble/event key/value line. inEvent tracks whether
// we are inside the Event block (so its trailing detail lines are collected).
func (ms *Microstackshot) parseField(line string, inEvent bool) bool {
	key, val, ok := splitField(line)
	if !ok {
		if inEvent && strings.TrimSpace(line) == "" {
			return false // blank line ends the Event block
		}
		return inEvent
	}
	switch key {
	case "Command":
		ms.Command = val
	case "Path":
		if ms.Path == "" {
			ms.Path = val
		}
	case "PID":
		ms.PID, _ = strconv.Atoi(val)
	case "OS Version":
		ms.OSVersion = val
	case "Architecture":
		if ms.Architecture == "" {
			ms.Architecture = val
		}
	case "Data Source":
		ms.DataSource = val
	case "Shared Cache":
		ms.SharedCache = val
	case "Hardware model":
		ms.HardwareModel = val
	case "Memory size":
		ms.MemorySize = val
	case "Event":
		ms.Event, inEvent = val, true
	case "Action taken":
		ms.ActionTaken = val
	default:
		if inEvent {
			ms.EventDetail = append(ms.EventDetail, strings.TrimSpace(line))
		}
	}
	return inEvent
}

// splitField splits an aligned "Key:        value" line on its first colon.
func splitField(line string) (key, val string, ok bool) {
	if line == "" || line[0] == ' ' || line[0] == '\t' {
		return "", "", false // indented lines are not top-level fields
	}
	before, after, ok0 := strings.Cut(line, ":")
	if !ok0 {
		return "", "", false
	}
	return strings.TrimSpace(before), strings.TrimSpace(after), true
}

func parseFrame(line string) (MicrostackFrame, bool) {
	m := frameRe.FindStringSubmatch(line)
	if m == nil {
		return MicrostackFrame{}, false
	}
	f := MicrostackFrame{Symbol: m[2], Image: m[3]}
	f.Count, _ = strconv.Atoi(m[1])
	f.Offset, _ = strconv.ParseUint(m[4], 10, 64)
	if m[5] != "" {
		f.Addr, _ = strconv.ParseUint(m[5], 0, 64)
	}
	return f, true
}

// Symbolicate resolves the heaviest-stack frames still showing "???" against an
// open dyld_shared_cache. Frames whose image is not in the cache (the main
// executable, loose dylibs) are left as image+offset. Mirrors the 109 path.
func (ms *Microstackshot) Symbolicate(f *dyld.File) {
	for idx := range ms.HeaviestStack {
		fr := &ms.HeaviestStack[idx]
		if fr.Symbol != "???" && fr.Symbol != "" {
			continue
		}
		if sym, ok := resolveMicrostackFrame(f, fr.Image, fr.Offset); ok {
			fr.Symbol = sym
		}
	}
}

// resolveMicrostackFrame maps (image, offset-into-image) to a symbol in the DSC.
// The microstackshot offset is image-load-address-relative, so the unslid vmaddr
// is image.LoadAddress + offset (empirically verified against a real cache).
func resolveMicrostackFrame(f *dyld.File, imageName string, offset uint64) (string, bool) {
	image, err := f.Image(imageName)
	if err != nil { // ImageNotFoundError: frame is the main exe or a loose dylib
		return "", false
	}
	unslid := image.CacheImageTextInfo.LoadAddress + offset
	if sym, ok := lookupSym(f, unslid); ok {
		return sym, true
	}
	// Analyze() lazily populates the cache-wide symbol table, then seed the
	// cross-image patchable exports it does not set itself.
	if err := image.Analyze(); err != nil {
		return "", false
	}
	for _, patch := range image.PatchableExports {
		if addr, err := image.GetVMAddress(uint64(patch.GetImplOffset())); err == nil {
			f.AddressToSymbol.Set(addr, patch.GetName())
		}
	}
	return lookupSym(f, unslid)
}

// lookupSym resolves an unslid vmaddr to a symbol: exact hit first, else the
// enclosing function start plus a byte delta.
func lookupSym(f *dyld.File, unslid uint64) (string, bool) {
	if sym, ok := f.AddressToSymbol.Get(unslid); ok {
		return sym, true
	}
	if img, err := f.GetImageContainingVMAddr(unslid); err == nil {
		if m, err := img.GetMacho(); err == nil {
			defer m.Close()
			if fn, err := m.GetFunctionForVMAddr(unslid); err == nil {
				if sym, ok := f.AddressToSymbol.Get(fn.StartAddr); ok {
					return fmt.Sprintf("%s + %d", sym, unslid-fn.StartAddr), true
				}
			}
		}
	}
	return "", false
}

func (ms *Microstackshot) String() string {
	var out strings.Builder
	when := ms.Header.Timestamp.Format("02Jan2006 15:04:05")
	out.WriteString(fmt.Sprintf("[%s] - %s - %s\n\n", colorTime(when), colorError(ms.Header.BugTypeDesc), colorImage("%s", ms.Header.Name)))

	buf := bytes.NewBufferString("")
	w := tabwriter.NewWriter(buf, 0, 0, 2, ' ', 0)
	if ms.Event != "" {
		action := ms.ActionTaken
		if action == "" {
			action = "none"
		}
		fmt.Fprintf(w, "%s\t%s (action taken: %s)\n", colorField("Event"), colorError(ms.Event), action)
	}
	if ms.Command != "" {
		fmt.Fprintf(w, "%s\t%s [%d]\n", colorField("Process"), colorImage("%s", ms.Command), ms.PID)
	}
	if ms.Path != "" {
		fmt.Fprintf(w, "%s\t%s\n", colorField("Path"), ms.Path)
	}
	if ms.OSVersion != "" {
		fmt.Fprintf(w, "%s\t%s\n", colorField("OS Version"), ms.OSVersion)
	}
	if ms.HardwareModel != "" {
		fmt.Fprintf(w, "%s\t%s\n", colorField("Hardware"), ms.HardwareModel)
	}
	w.Flush()
	out.WriteString(buf.String())

	if len(ms.EventDetail) > 0 {
		out.WriteString("\n" + colorField("Limit") + ":\n")
		for _, d := range ms.EventDetail {
			out.WriteString("  " + d + "\n")
		}
	}

	if len(ms.HeaviestStack) > 0 {
		out.WriteString(fmt.Sprintf("\n%s %s:\n", colorField("Heaviest stack for"), colorImage("%s", ms.Command)))
		out.WriteString(ms.stackString())
	}
	return out.String()
}

func (ms *Microstackshot) stackString() string {
	buf := bytes.NewBufferString("")
	w := tabwriter.NewWriter(buf, 0, 0, 2, ' ', 0)
	for idx, f := range ms.HeaviestStack {
		loc := colorAddr("+ %d", f.Offset) // unsymbolicated: show the offset into the image
		if f.Symbol != "???" && f.Symbol != "" {
			loc = colorField(f.Symbol)
		}
		fmt.Fprintf(w, "  %2d: %s\t%s\t%s\n", idx, colorBold("%d samples", f.Count), colorImage("%s", f.Image), loc)
	}
	w.Flush()
	return buf.String()
}
