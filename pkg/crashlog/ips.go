package crashlog

import (
	"bytes"
	"compress/gzip"
	_ "embed"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/AlecAivazis/survey/v2"
	"github.com/AlecAivazis/survey/v2/terminal"
	"github.com/apex/log"
	"github.com/blacktop/arm64-cgo/disassemble"
	"github.com/blacktop/go-macho"
	"github.com/blacktop/go-macho/pkg/swift"
	"github.com/blacktop/go-macho/types"
	"github.com/blacktop/ipsw/internal/colors"
	"github.com/blacktop/ipsw/internal/commands/dsc"
	"github.com/blacktop/ipsw/internal/commands/extract"
	"github.com/blacktop/ipsw/internal/demangle"
	"github.com/blacktop/ipsw/internal/search"
	"github.com/blacktop/ipsw/internal/syms/server"
	"github.com/blacktop/ipsw/pkg/disass"
	"github.com/blacktop/ipsw/pkg/info"
	"github.com/blacktop/ipsw/pkg/signature"
	"github.com/go-viper/mapstructure/v2"
)

// REFERENCES:
//     - https://developer.apple.com/documentation/xcode/interpreting-the-json-format-of-a-crash-report
//     - https://github.com/zed-industries/zed/blob/main/crates/collab/src/api/ips_file.rs

//go:embed data/log_type.gz
var logTypeData []byte

var colorTime = colors.BoldHiGreen().SprintFunc()
var colorError = colors.BoldHiRed().SprintFunc()
var colorAddr = colors.Faint().SprintfFunc()
var colorBold = colors.Bold().SprintfFunc()
var colorImage = colors.BoldHiMagenta().SprintfFunc()
var colorField = colors.BoldHiBlue().SprintFunc()

var ErrDone = errors.New("done")

type LogType struct {
	Name       string `json:"name"`
	Comment    string `json:"comment,omitempty"`
	Extention  string `json:"ext,omitempty"`
	EOS        bool   `json:"eOS,omitempty"`
	Gm         bool   `json:"gm,omitempty"`
	Legacy     bool   `json:"legacy,omitempty"`
	MacOS      bool   `json:"macOS,omitempty"`
	Disabled   bool   `json:"disabled,omitempty"`
	WatchSync  bool   `json:"watchSync,omitempty"`
	Limit      int    `json:"limit,omitempty"`
	Radar      string `json:"radar,omitempty"`
	Seed       bool   `json:"seed,omitempty"`
	Routing    string `json:"routing,omitempty"`
	Subrouting string `json:"subrouting,omitempty"`
}

// LogTypes from /System/Library/PrivateFrameworks/OSAnalytics.framework/Versions/A/Resources/submissionConfig.plist
type LogTypes map[string]LogType

type DB struct {
	LogTypes           LogTypes       `json:"log_types"`
	SubmissionParams   map[string]any `json:"submission_params"`
	WhitelistedDomains map[string]any `json:"whitelisted_domains"`
}

func GetLogTypes() (*LogTypes, error) {
	var db DB

	zr, err := gzip.NewReader(bytes.NewReader(logTypeData))
	if err != nil {
		return nil, err
	}
	defer zr.Close()

	if err := json.NewDecoder(zr).Decode(&db); err != nil {
		return nil, fmt.Errorf("failed unmarshaling ipsw_db data: %w", err)
	}

	return &db.LogTypes, nil
}

type Config struct {
	All           bool
	Running       bool
	Process       string
	Unslid        bool
	KernelSlide   uint64 // Custom KASLR slide to apply to kernel frames for live debugging
	DSCSlide      uint64 // Custom slide to apply to dyld_shared_cache frames for live debugging
	Demangle      bool
	Hex           bool
	Verbose       bool
	Peek          bool
	PeekCount     int // Number of instructions to show with --peek (default 5)
	PemDB         string
	SignaturesDir string
	ExtrasDir     string
	IDAScript     bool   // Generate IDAPython script to mark panic frames
	CrashlogPath  string // Path to the crashlog file (set automatically by OpenIPS)
}

type Ips struct {
	Header        IpsMetadata
	Payload       IPSPayload
	Config        *Config
	KernelSymbols signature.SymbolMap // Symbols discovered via --signatures flag
}

type Platform int

const (
	PlatformMacOS            Platform = 1
	PlatformIOS              Platform = 2 // (includes iOS apps running under macOS on Apple silicon)
	PlatformTVOS             Platform = 3
	PlatformWatch            Platform = 4
	PlatformMacCatalyst      Platform = 6
	PlatformIOSSimulator     Platform = 7
	PlatformTVOSSimulator    Platform = 8
	PlatformWatchOSSimulator Platform = 9
)

func (p Platform) String() string {
	switch p {
	case PlatformMacOS:
		return "macOS"
	case PlatformIOS:
		return "iOS"
	case PlatformTVOS:
		return "tvOS"
	case PlatformWatch:
		return "watchOS"
	case PlatformMacCatalyst:
		return "Mac Catalyst"
	case PlatformIOSSimulator:
		return "iOS Simulator"
	case PlatformTVOSSimulator:
		return "tvOS Simulator"
	case PlatformWatchOSSimulator:
		return "watchOS Simulator"
	default:
		return "Unknown"
	}
}

type Timestamp time.Time

func (ts *Timestamp) UnmarshalJSON(b []byte) error {
	s := strings.Trim(string(b), "\"")
	if s == "null" || s == "" {
		return nil
	}
	// 2023-08-04 19:10:03.00 +0200
	t, err := time.Parse("2006-01-02 15:04:05 -0700", s)
	if err != nil {
		return err
	}
	*ts = Timestamp(t)
	return nil
}
func (r Timestamp) MarshalJSON() ([]byte, error) {
	return json.Marshal(time.Time(r))
}
func (r Timestamp) Format(s string) string {
	t := time.Time(r)
	return t.Format(s)
}

type IpsMetadata struct {
	Name             string    `json:"name,omitempty"`
	AppName          string    `json:"app_name,omitempty"`
	AppVersion       string    `json:"app_version,omitempty"`
	BugType          string    `json:"bug_type,omitempty"`
	BugTypeDesc      string    `json:"bug_type_desc,omitempty"`
	OsVersion        string    `json:"os_version,omitempty"`
	BundleID         string    `json:"bundleID,omitempty"`
	BuildVersion     string    `json:"build_version,omitempty"`
	IncidentID       string    `json:"incident_id,omitempty"`
	Platform         Platform  `json:"platform,omitempty"`
	Timestamp        Timestamp `json:"timestamp"`
	SliceUUID        string    `json:"slice_uuid,omitempty"`
	ShareWithAppDevs int       `json:"share_with_app_devs,omitempty"`
	IsFirstParty     int       `json:"is_first_party,omitempty"`
	RootsInstalled   int       `json:"roots_installed,omitempty"`
}

func (m IpsMetadata) Version() string {
	re := regexp.MustCompile(`(?P<version>[0-9.]+) \((?P<build>\w+)\)$`)
	matches := re.FindStringSubmatch(m.OsVersion)
	if len(matches) != 3 {
		return m.OsVersion
	}
	return matches[1]
}
func (m IpsMetadata) Build() string {
	re := regexp.MustCompile(`(?P<version>[0-9.]+) \((?P<build>\w+)\)$`)
	matches := re.FindStringSubmatch(m.OsVersion)
	if len(matches) != 3 {
		return m.OsVersion
	}
	return matches[2]
}

type MemoryStatus struct {
	BusyBufferCount int64 `json:"busyBufferCount,omitempty"`
	Compressions    int64 `json:"compressions,omitempty"`
	CompressorSize  int64 `json:"compressorSize,omitempty"`
	Decompressions  int64 `json:"decompressions,omitempty"`
	MemoryPages     struct {
		Active      int64 `json:"active,omitempty"`
		FileBacked  int64 `json:"fileBacked,omitempty"`
		Free        int64 `json:"free,omitempty"`
		Inactive    int64 `json:"inactive,omitempty"`
		Purgeable   int64 `json:"purgeable,omitempty"`
		Speculative int64 `json:"speculative,omitempty"`
		Throttled   int64 `json:"throttled,omitempty"`
		Wired       int64 `json:"wired,omitempty"`
	} `json:"memoryPages"`
	MemoryPressure        bool `json:"memoryPressure,omitempty"`
	MemoryPressureDetails struct {
		PagesReclaimed int64 `json:"pagesReclaimed,omitempty"`
		PagesWanted    int64 `json:"pagesWanted,omitempty"`
	} `json:"memoryPressureDetails"`
	PageSize int64 `json:"pageSize,omitempty"`
}

func (ms MemoryStatus) String() string {
	return fmt.Sprintf(
		"%s:\n"+
			"  %s: %d\n"+
			"  %s: %d\n"+
			"  %s: %d\n"+
			"  %s: %d\n"+
			"  %s:\n"+
			"    %s: %d\n"+
			"    %s: %d\n"+
			"    %s: %d\n"+
			"    %s: %d\n"+
			"    %s: %d\n"+
			"    %s: %d\n"+
			"    %s: %d\n"+
			"    %s: %d\n"+
			"  %s: %t\n"+
			"  %s:\n"+
			"    %s: %d\n"+
			"    %s: %d\n"+
			"  %s: %d\n",
		colorField("Memory Status"),
		colorField("Busy Buffer Count"), ms.BusyBufferCount,
		colorField("Compressions"), ms.Compressions,
		colorField("Compressor Size"), ms.CompressorSize,
		colorField("Decompressions"), ms.Decompressions,
		colorField("Memory Pages"),
		colorField("Active"), ms.MemoryPages.Active,
		colorField("File Backed"), ms.MemoryPages.FileBacked,
		colorField("Free"), ms.MemoryPages.Free,
		colorField("Inactive"), ms.MemoryPages.Inactive,
		colorField("Purgeable"), ms.MemoryPages.Purgeable,
		colorField("Speculative"), ms.MemoryPages.Speculative,
		colorField("Throttled"), ms.MemoryPages.Throttled,
		colorField("Wired"), ms.MemoryPages.Wired,
		colorField("Memory Pressure"), ms.MemoryPressure,
		colorField("Memory Pressure Details"),
		colorField("Pages Reclaimed"), ms.MemoryPressureDetails.PagesReclaimed,
		colorField("Pages Wanted"), ms.MemoryPressureDetails.PagesWanted,
		colorField("Page Size"), ms.PageSize,
	)
}

type Process struct {
	ID                  int            `json:"pid"`
	Name                string         `json:"procname"`
	TimesThrottled      int            `json:"timesThrottled"`
	TurnstileInfo       []string       `json:"turnstileInfo"`
	PageIns             int            `json:"pageIns"`
	WaitInfo            []string       `json:"waitInfo"`
	TimesDidThrottle    int            `json:"timesDidThrottle"`
	CopyOnWriteFaults   int            `json:"copyOnWriteFaults"`
	PageFaults          int            `json:"pageFaults"`
	UserTimeTask        float64        `json:"userTimeTask"`
	SystemTimeTask      float64        `json:"systemTimeTask"`
	Flags               []string       `json:"flags"`
	ResidentMemoryBytes int            `json:"residentMemoryBytes"`
	ThreadByID          map[int]Thread `json:"threadById,omitempty"`
}

type Thread struct {
	ID                 int          `json:"id"`
	Name               string       `json:"name,omitempty"`
	State              []string     `json:"state"`
	Continuation       []int        `json:"continuation,omitempty"`
	Queue              string       `json:"queue,omitempty"`
	DispatchQueueLabel string       `json:"dispatch_queue_label,omitempty"`
	SchedFlags         []string     `json:"schedFlags,omitempty"`
	BasePriority       int          `json:"basePriority"`
	UserFrames         []PanicFrame `json:"userFrames"`
	KernelFrames       []PanicFrame `json:"kernelFrames,omitempty"`
	WaitEvent          []float64    `json:"waitEvent,omitempty"`
	QosRequested       string       `json:"qosRequested,omitempty"`
	QosEffective       string       `json:"qosEffective,omitempty"`
	UserTime           float64      `json:"userTime"`
	UserUsec           int          `json:"user_usec"`
	SystemTime         float64      `json:"systemTime"`
	SystemUsec         int          `json:"system_usec"`
	SchedPriority      int          `json:"schedPriority"`
}

type BinaryImage struct {
	Arch   string `json:"arch,omitempty"`
	Base   uint64 `json:"base,omitempty"`
	Name   string `json:"name,omitempty"`
	Path   string `json:"path,omitempty"`
	Size   uint64 `json:"size,omitempty"`
	Source string `json:"source,omitempty"`
	UUID   string `json:"uuid,omitempty"`
	Slide  uint64 `json:"slide,omitempty"`
}

func (bi *BinaryImage) UnmarshalJSON(b []byte) error {
	var raw []json.RawMessage
	if err := json.Unmarshal(b, &raw); err != nil {
		return err
	}
	if err := json.Unmarshal(raw[0], &bi.UUID); err != nil {
		return err
	}
	if err := json.Unmarshal(raw[1], &bi.Base); err != nil {
		return err
	}
	if err := json.Unmarshal(raw[2], &bi.Source); err != nil {
		return err
	}
	switch bi.Source {
	case "P":
		bi.Source = "Process"
	case "S":
		bi.Source = "SharedCache"
	case "C":
		bi.Source = "SharedCacheLibrary"
	case "K":
		bi.Source = "Kernel"
	case "U":
		bi.Source = "KernelCache"
	case "T":
		bi.Source = "KernelTextExec"
	case "A":
		bi.Source = "Absolute"
	default:
		return fmt.Errorf("invalid binary image source: %v", bi.Source)
	}
	return nil
}

type OsVersion struct {
	ReleaseType string `json:"releaseType,omitempty"`
	Build       string `json:"build,omitempty"`
	Train       string `json:"train,omitempty"`
	IsEmbedded  bool   `json:"isEmbedded,omitempty"`
}

type BundleInfo struct {
	CFBundleIdentifier         string `json:"CFBundleIdentifier,omitempty"`
	CFBundleShortVersionString string `json:"CFBundleShortVersionString,omitempty"`
	CFBundleVersion            string `json:"CFBundleVersion,omitempty"`
	DTAppStoreToolsBuild       string `json:"DTAppStoreToolsBuild,omitempty"`
}

type StoreInfo struct {
	ItemID                            string `json:"itemID,omitempty"`
	StoreCohortMetadata               string `json:"storeCohortMetadata,omitempty"`
	DistributorID                     string `json:"distributorID,omitempty"`
	ApplicationVariant                string `json:"applicationVariant,omitempty"`
	DeviceIdentifierForVendor         string `json:"deviceIdentifierForVendor,omitempty"`
	SoftwareVersionExternalIdentifier string `json:"softwareVersionExternalIdentifier,omitempty"`
	ThirdParty                        bool   `json:"thirdParty,omitempty"`
}

type Exception struct {
	Codes    string `json:"codes,omitempty"`
	RawCodes []int  `json:"rawCodes,omitempty"`
	Message  string `json:"message,omitempty"`
	Signal   string `json:"signal,omitempty"`
	Type     string `json:"type,omitempty"`
	Subtype  string `json:"subtype,omitempty"`
}

func fmtAddr(val uint64) string {
	if val == 0 {
		return colorAddr("%#016x", val)
	}
	return fmt.Sprintf("%#016x", val)
}
func fmtAddrSmol(val uint64) string {
	if val == 0 {
		return colorAddr("%#08x", val)
	}
	return fmt.Sprintf("%#08x", val)
}

type Register struct {
	Value             uint64 `json:"value,omitempty"`
	SymbolLocation    uint64 `json:"symbolLocation,omitempty"`
	Symbol            string `json:"symbol,omitempty"`
	Description       string `json:"description,omitempty"`
	MatchesCrashFrame int    `json:"matchesCrashFrame,omitempty"`
}

func (r Register) String() string {
	var out strings.Builder
	out.WriteString(fmtAddr(r.Value))
	if r.SymbolLocation != 0 {
		out.WriteString(fmt.Sprintf(" %s", colorAddr("%#016x", r.SymbolLocation)))
	}
	if len(r.Symbol) > 0 {
		out.WriteString(fmt.Sprintf(" %s", colorImage(r.Symbol)))
	}
	if len(r.Description) > 0 {
		out.WriteString(" " + colorField(r.Description))
	}
	if r.MatchesCrashFrame != 0 {
		out.WriteString(colorBold(" matches_crash_frame=%d", r.MatchesCrashFrame))
	}
	return out.String()
}

type ThreadState struct {
	X      []Register `json:"x,omitempty"`
	Flavor string     `json:"flavor,omitempty"`
	LR     Register   `json:"lr"`
	CPSR   Register   `json:"cpsr"`
	FP     Register   `json:"fp"`
	SP     Register   `json:"sp"`
	ESR    Register   `json:"esr"`
	PC     Register   `json:"pc"`
	FAR    Register   `json:"far"`
}

func (s ThreadState) HasSymbols() bool {
	for _, reg := range s.X {
		if len(reg.Symbol) > 0 {
			return true
		}
	}
	if len(s.LR.Symbol) > 0 {
		return true
	}
	if len(s.FP.Symbol) > 0 {
		return true
	}
	if len(s.SP.Symbol) > 0 {
		return true
	}
	if len(s.PC.Symbol) > 0 {
		return true
	}
	if len(s.ESR.Symbol) > 0 {
		return true
	}
	return false
}

func (s ThreadState) String() string {
	if s.HasSymbols() {
		var out strings.Builder
		for i, reg := range s.X {
			out.WriteString(fmt.Sprintf("  %3s: %s\n", fmt.Sprintf("x%d", i), reg))
		}
		out.WriteString(fmt.Sprintf("   fp: %s\n", s.FP))
		out.WriteString(fmt.Sprintf("   lr: %s\n", s.LR))
		out.WriteString(fmt.Sprintf("   sp: %s\n", s.SP))
		out.WriteString(fmt.Sprintf("   pc: %s\n", s.PC))
		out.WriteString(fmt.Sprintf("  far: %s\n", s.FAR))
		out.WriteString(fmt.Sprintf(" cpsr: %s\n", s.CPSR))
		out.WriteString(fmt.Sprintf("  esr: %s\n", s.ESR))
		return out.String()
	} else {
		return fmt.Sprintf(
			"    x0: %s   x1: %s   x2: %s   x3: %s\n"+
				"    x4: %s   x5: %s   x6: %s   x7: %s\n"+
				"    x8: %s   x9: %s  x10: %s  x11: %s\n"+
				"   x12: %s  x13: %s  x14: %s  x15: %s\n"+
				"   x16: %s  x17: %s  x18: %s  x19: %s\n"+
				"   x20: %s  x21: %s  x22: %s  x23: %s\n"+
				"   x24: %s  x25: %s  x26: %s  x27: %s\n"+
				"   x28: %s   fp: %s   lr: %s\n"+
				"    sp: %s   pc: %s cpsr: %s\n"+
				"   esr: %s %s\n",
			fmtAddr(s.X[0].Value), fmtAddr(s.X[1].Value), fmtAddr(s.X[2].Value), fmtAddr(s.X[3].Value),
			fmtAddr(s.X[4].Value), fmtAddr(s.X[5].Value), fmtAddr(s.X[6].Value), fmtAddr(s.X[7].Value),
			fmtAddr(s.X[8].Value), fmtAddr(s.X[9].Value), fmtAddr(s.X[10].Value), fmtAddr(s.X[11].Value),
			fmtAddr(s.X[12].Value), fmtAddr(s.X[13].Value), fmtAddr(s.X[14].Value), fmtAddr(s.X[15].Value),
			fmtAddr(s.X[16].Value), fmtAddr(s.X[17].Value), fmtAddr(s.X[18].Value), fmtAddr(s.X[19].Value),
			fmtAddr(s.X[20].Value), fmtAddr(s.X[21].Value), fmtAddr(s.X[22].Value), fmtAddr(s.X[23].Value),
			fmtAddr(s.X[24].Value), fmtAddr(s.X[25].Value), fmtAddr(s.X[26].Value), fmtAddr(s.X[27].Value),
			fmtAddr(s.X[28].Value), fmtAddr(s.FP.Value), fmtAddr(s.LR.Value),
			fmtAddr(s.SP.Value), fmtAddr(s.PC.Value), fmtAddrSmol(s.CPSR.Value),
			fmtAddrSmol(s.ESR.Value), colorField(s.ESR.Description))
	}
}

type UserThread struct {
	Frames      []Frame     `json:"frames,omitempty"`
	ID          int         `json:"id,omitempty"`
	Name        string      `json:"name,omitempty"`
	Queue       string      `json:"queue,omitempty"`
	ThreadState ThreadState `json:"threadState"`
	Triggered   bool        `json:"triggered,omitempty"`
}

type Frame struct {
	ImageIndex     uint64 `json:"imageIndex,omitempty"`
	ImageOffset    uint64 `json:"imageOffset,omitempty"`
	Symbol         string `json:"symbol,omitempty"`
	SymbolLocation uint64 `json:"symbolLocation,omitempty"`
	Slide          uint64 `json:"slide,omitempty"`
}

type PanicFrame struct {
	ImageIndex     uint64 `json:"imageIndex,omitempty"`
	ImageName      string `json:"imageName,omitempty"`
	ImageOffset    uint64 `json:"imageOffset,omitempty"`
	Symbol         string `json:"symbol,omitempty"`
	SymbolLocation uint64 `json:"symbolLocation,omitempty"`
	Slide          uint64 `json:"slide,omitempty"`
	// PeekBytes holds ARM64 instructions around the frame address for --peek disassembly
	PeekBytes []byte `json:"-"`
	// PeekAddr is the starting address of PeekBytes
	PeekAddr uint64 `json:"-"`
	// PeekFrameIdx is the index of the frame instruction within PeekBytes (in instructions, not bytes)
	PeekFrameIdx int `json:"-"`
	// PeekSymbols maps addresses to symbol names for enriching branch target disassembly
	PeekSymbols map[uint64]string `json:"-"`
}

func (pf *PanicFrame) UnmarshalJSON(b []byte) error {
	var s [2]uint64
	if err := json.Unmarshal(b, &s); err != nil {
		return err
	}
	*pf = PanicFrame{
		ImageIndex:  s[0],
		ImageName:   fmt.Sprintf("image_%d", s[0]),
		ImageOffset: s[1],
	}
	return nil
}

type Termination struct {
	ByPid     int    `json:"byPid,omitempty"`
	ByProc    string `json:"byProc,omitempty"`
	Code      int    `json:"code,omitempty"`
	Flags     int    `json:"flags,omitempty"` // https://opensource.apple.com/source/xnu/xnu-3789.21.4/bsd/sys/reason.h.auto.html
	Indicator string `json:"indicator,omitempty"`
	Namespace string `json:"namespace,omitempty"`
}

type PostSampleVMStats struct {
	Faults                             int `json:"faults,omitempty"`
	ActiveCount                        int `json:"active_count,omitempty"`
	CompressorPageCount                int `json:"compressorPageCount,omitempty"`
	TotalUncompressedPagesInCompressor int `json:"total_uncompressed_pages_in_compressor,omitempty"`
	Hits                               int `json:"hits,omitempty"`
	Decompressions                     int `json:"decompressions,omitempty"`
	Swapouts                           int `json:"swapouts,omitempty"`
	WireCount                          int `json:"wire_count,omitempty"`
	Lookups                            int `json:"lookups,omitempty"`
	Purges                             int `json:"purges,omitempty"`
	Pageouts                           int `json:"pageouts,omitempty"`
	Pageins                            int `json:"pageins,omitempty"`
	ExternalPageCount                  int `json:"external_page_count,omitempty"`
	ZeroFillCount                      int `json:"zero_fill_count,omitempty"`
	FreeCount                          int `json:"free_count,omitempty"`
	CowFaults                          int `json:"cow_faults,omitempty"`
	SpeculativeCount                   int `json:"speculative_count,omitempty"`
	Swapins                            int `json:"swapins,omitempty"`
	Compressions                       int `json:"compressions,omitempty"`
	Reactivations                      int `json:"reactivations,omitempty"`
	InactiveCount                      int `json:"inactive_count,omitempty"`
	ThrottledCount                     int `json:"throttled_count,omitempty"`
	PurgeableCount                     int `json:"purgeable_count,omitempty"`
	InternalPageCount                  int `json:"internal_page_count,omitempty"`
}

type AdditionalDetails struct {
	StackshotDurationOuterNsec int `json:"stackshot_duration_outer_nsec,omitempty"`
	StackshotInFlags           int `json:"stackshot_in_flags,omitempty"`
	StackshotThreadsCount      int `json:"stackshot_threads_count,omitempty"`
	StackshotDurationPriorNsec int `json:"stackshot_duration_prior_nsec,omitempty"`
	StackshotSizeEstimateAdj   int `json:"stackshot_size_estimate_adj,omitempty"`
	StackshotOutFlags          int `json:"stackshot_out_flags,omitempty"`
	StackshotTasksCount        int `json:"stackshot_tasks_count,omitempty"`
	StackshotInPid             int `json:"stackshot_in_pid,omitempty"`
	StackshotSizeEstimate      int `json:"stackshot_size_estimate,omitempty"`
	StackshotTries             int `json:"stackshot_tries,omitempty"`
	StackshotDurationNsec      int `json:"stackshot_duration_nsec,omitempty"`
	SystemStateFlags           int `json:"system_state_flags,omitempty"`
}

type IPSPayload struct {
	/* Kernelspace Fields */
	Build            string          `json:"build,omitempty"`
	Product          string          `json:"product,omitempty"`
	SocID            string          `json:"socId,omitempty"`
	Kernel           string          `json:"kernel,omitempty"`
	Incident         string          `json:"incident,omitempty"`
	CrashReporterKey string          `json:"crashReporterKey,omitempty"`
	Date             string          `json:"date,omitempty"`
	PanicString      string          `json:"panicString,omitempty"`
	MacOSPanicString string          `json:"macOSPanicString,omitempty"`
	PanicFlags       string          `json:"panicFlags,omitempty"`
	OtherString      string          `json:"otherString,omitempty"`
	MemoryStatus     MemoryStatus    `json:"memoryStatus"`
	ProcessByPid     map[int]Process `json:"processByPid,omitempty"`
	BinaryImages     []BinaryImage   `json:"binaryImages,omitempty"`
	Notes            []string        `json:"notes,omitempty"`
	/* Userspace Fields */
	Asi map[string][]string `json:"asi,omitempty"` // Additional application-specific logging. The properties of this object include an array of log strings.
	// For more information, see Diagnostic messages. This appears in a translated report under Application Specific Information.
	// https://developer.apple.com/documentation/xcode/examining-the-fields-in-a-crash-report#Diagnostic-messages
	IsCorpse              any        `json:"isCorpse,omitempty"`
	IsNonFatal            string     `json:"isNonFatal,omitempty"`
	IsSimulated           string     `json:"isSimulated,omitempty"`
	Uptime                int        `json:"uptime,omitempty"`
	Translated            bool       `json:"translated,omitempty"`
	ProcName              string     `json:"procName,omitempty"`
	ProcPath              string     `json:"procPath,omitempty"`
	ProcRole              string     `json:"procRole,omitempty"`
	ProcLaunch            string     `json:"procLaunch,omitempty"`
	ProcStartAbsTime      int64      `json:"procStartAbsTime,omitempty"`
	ProcExitAbsTime       int64      `json:"procExitAbsTime,omitempty"`
	UserID                int        `json:"userID,omitempty"`
	DeployVersion         int        `json:"deployVersion,omitempty"`
	ModelCode             string     `json:"modelCode,omitempty"`
	CoalitionID           int        `json:"coalitionID,omitempty"`
	OsVersion             OsVersion  `json:"osVersion"`
	CaptureTime           string     `json:"captureTime,omitempty"`
	PID                   int        `json:"pid,omitempty"`
	CPUType               string     `json:"cpuType,omitempty"`
	RootsInstalled        int        `json:"roots_installed,omitempty"`
	BugType               string     `json:"bug_type,omitempty"`
	BundleInfo            BundleInfo `json:"bundleInfo"`
	StoreInfo             StoreInfo  `json:"storeInfo"`
	ParentProc            string     `json:"parentProc,omitempty"`
	ParentPid             int        `json:"parentPid,omitempty"`
	CoalitionName         string     `json:"coalitionName,omitempty"`
	LockdownMode          int        `json:"ldm,omitempty"`
	WasUnlockedSinceBoot  int        `json:"wasUnlockedSinceBoot,omitempty"`
	IsLocked              int        `json:"isLocked,omitempty"`
	InstructionByteStream struct {
		BeforePC string `json:"beforePC,omitempty"`
		AtPC     string `json:"atPC,omitempty"`
	} `json:"instructionByteStream"`
	CodeSigningID                 string       `json:"codeSigningID,omitempty"`
	CodeSigningTeamID             string       `json:"codeSigningTeamID,omitempty"`
	CodeSigningFlags              int          `json:"codeSigningFlags,omitempty"`
	CodeSigningValidationCategory int          `json:"codeSigningValidationCategory,omitempty"`
	CodeSigningTrustLevel         int          `json:"codeSigningTrustLevel,omitempty"`
	CodeSigningMonitor            int          `json:"codeSigningMonitor,omitempty"`
	ThrottleTimeout               int64        `json:"throttleTimeout,omitempty"`
	BasebandVersion               string       `json:"basebandVersion,omitempty"`
	Exception                     any          `json:"exception,omitempty"`
	LastExceptionBacktrace        []Frame      `json:"lastExceptionBacktrace,omitempty"`
	FaultingThread                int          `json:"faultingThread,omitempty"`
	Threads                       []UserThread `json:"threads,omitempty"`
	UsedImages                    []struct {
		Arch   string `json:"arch,omitempty"`
		Base   uint64 `json:"base,omitempty"`
		Name   string `json:"name,omitempty"`
		Path   string `json:"path,omitempty"`
		Size   uint64 `json:"size,omitempty"`
		Source string `json:"source,omitempty"`
		UUID   string `json:"uuid,omitempty"`
	} `json:"usedImages,omitempty"`
	SharedCache struct {
		Base uint64 `json:"base,omitempty"`
		Size uint64 `json:"size,omitempty"`
		UUID string `json:"uuid,omitempty"`
	} `json:"sharedCache"`
	LegacyInfo struct {
		ThreadTriggered struct {
			Queue string `json:"queue,omitempty"`
		} `json:"threadTriggered"`
	} `json:"legacyInfo"`
	TrialInfo struct {
		Rollouts []struct {
			RolloutID     string `json:"rolloutId,omitempty"`
			FactorPackIds struct {
			} `json:"factorPackIds"`
			DeploymentID int `json:"deploymentId,omitempty"`
		} `json:"rollouts,omitempty"`
		Experiments []struct {
			TreatmentID  string `json:"treatmentId,omitempty"`
			ExperimentID string `json:"experimentId,omitempty"`
			DeploymentID int    `json:"deploymentId,omitempty"`
		} `json:"experiments,omitempty"`
	} `json:"trialInfo"`
	DTAppStoreToolsBuild string      `json:"DTAppStoreToolsBuild,omitempty"`
	Version              int         `json:"version,omitempty"`
	VMSummary            string      `json:"vmSummary,omitempty"`
	VmRegionInfo         string      `json:"vmregioninfo,omitempty"`
	Termination          Termination `json:"termination"`

	AbsoluteTime      int               `json:"absoluteTime,omitempty"`
	PostSampleVMStats PostSampleVMStats `json:"postSampleVMStats"`
	AdditionalDetails AdditionalDetails `json:"additionalDetails"`

	panic210 *Panic210
}

func ParseHeader(in string) (hdr *IpsMetadata, err error) {
	f, err := os.Open(in)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	if err := json.NewDecoder(f).Decode(&hdr); err != nil {
		return nil, fmt.Errorf("failed to decode JSON header (possibly unsupported .ips format): %w", err)
	}

	db, err := GetLogTypes()
	if err != nil {
		return nil, fmt.Errorf("failed to get log types database: %w", err)
	}

	if bt, ok := (*db)[hdr.BugType]; ok {
		hdr.BugTypeDesc = bt.Name
		if len(bt.Comment) > 0 {
			hdr.BugTypeDesc = hdr.BugType + " (" + bt.Comment + ")"
		}
	}

	return hdr, nil
}

func OpenIPS(in string, conf *Config) (*Ips, error) {
	ips := Ips{Config: conf}
	// Store the crashlog path for later use (e.g., IDA script generation)
	conf.CrashlogPath = in

	f, err := os.Open(in)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	// parse multi-line JSON
	dec := json.NewDecoder(f)
	if err := dec.Decode(&ips.Header); err != nil {
		return nil, err
	}
	if err := dec.Decode(&ips.Payload); err != nil {
		return nil, err
	}

	if len(ips.Payload.Product) == 0 {
		ips.Payload.Product = ips.Payload.ModelCode
	}

	db, err := GetLogTypes()
	if err != nil {
		return nil, fmt.Errorf("failed to get log types database: %w", err)
	}

	if bt, ok := (*db)[ips.Header.BugType]; ok {
		ips.Header.BugTypeDesc = bt.Name
		if len(bt.Comment) > 0 {
			ips.Header.BugTypeDesc = ips.Header.BugType + " (" + bt.Comment + ")"
		}
	}

	return &ips, nil
}

func demangleSym(do bool, in string) string {
	if do {
		if strings.HasPrefix(in, "__Z") || strings.HasPrefix(in, "_Z") {
			return demangle.Do(in, false, false)
		}
		if strings.HasPrefix(in, "_$s") || strings.HasPrefix(in, "$s") {
			in, _ = swift.Demangle(in)
		}
	}
	return in
}

// peekBytesReader is an interface for reading bytes at a virtual address
type peekBytesReader interface {
	ReadAtAddr(p []byte, addr uint64) (n int, err error)
}

// readPeekBytes reads ARM64 instructions around a frame address for --peek disassembly.
// count is the total number of instructions to show (centered on frame).
// funcStart is the function's start address (0 if unknown) - used to avoid reading before the function.
// Returns the bytes, the starting address, and the index of the frame instruction within the buffer.
//
// Centering logic:
//   - odd count (e.g. 5): equal before/after (2 before, frame, 2 after)
//   - even count (e.g. 4): fewer before (1 before, frame, 2 after)
//
// If frame is at/near function start, we shift instructions after to compensate.
func readPeekBytes(m peekBytesReader, frameAddr uint64, count int, funcStart, funcEnd uint64) ([]byte, uint64, int) {
	const instrSize = 4 // ARM64 instruction size

	if count < 1 {
		count = 1
	}

	// Calculate ideal number of instructions before/after
	// For odd count: equal split (5 -> 2 before, 1 frame, 2 after)
	// For even count: fewer before (4 -> 1 before, 1 frame, 2 after)
	numBefore := (count - 1) / 2
	numAfter := count - 1 - numBefore

	// Clamp numBefore if we'd read before function start
	if funcStart > 0 && frameAddr >= funcStart {
		maxBefore := int((frameAddr - funcStart) / instrSize)
		if numBefore > maxBefore {
			// Shift extra instructions to after
			extra := numBefore - maxBefore
			numBefore = maxBefore
			numAfter += extra
		}
	}

	// Also ensure we don't underflow the start address
	maxPossibleBefore := int(frameAddr / instrSize)
	if numBefore > maxPossibleBefore {
		extra := numBefore - maxPossibleBefore
		numBefore = maxPossibleBefore
		numAfter += extra
	}

	// Clamp numAfter if we'd read past function end
	if funcEnd > 0 && funcEnd > frameAddr {
		// funcEnd points to the first byte AFTER the function, so last valid instr starts at funcEnd-instrSize
		maxAfter := max(0, int((funcEnd-frameAddr)/instrSize)-1)
		if numAfter > maxAfter {
			numAfter = maxAfter
		}
	}

	totalInstrs := numBefore + 1 + numAfter
	startAddr := frameAddr - uint64(numBefore*instrSize)

	// Read the bytes
	buf := make([]byte, totalInstrs*instrSize)
	n, err := m.ReadAtAddr(buf, startAddr)
	if err != nil || n < len(buf) {
		return nil, 0, 0
	}
	return buf, startAddr, numBefore
}

// symbolLookup is an interface for looking up symbols by address
type symbolLookup interface {
	FindAddressSymbols(addr uint64) ([]macho.Symbol, error)
}

// extractPeekSymbols extracts symbol names for branch targets in peek bytes.
// peekAddr is the address to disassemble at (slid for user frames).
// slide is subtracted from branch targets before symbol lookup (for user frames with slide).
// The returned map uses slid addresses as keys to match formatPeekDisassembly lookups.
func extractPeekSymbols(peekBytes []byte, peekAddr uint64, slide uint64, lookup symbolLookup) map[uint64]string {
	if len(peekBytes) == 0 || lookup == nil {
		return nil
	}

	instructions, err := disassemble.GetInstructions(peekAddr, peekBytes)
	if err != nil {
		return nil
	}

	result := make(map[uint64]string)
	for _, block := range instructions.Blocks() {
		for _, instr := range block {
			// Check for branch instructions (B, BL)
			if instr.Operation == disassemble.ARM64_BL || instr.Operation == disassemble.ARM64_B {
				for _, operand := range instr.Operands {
					if operand.Class == disassemble.LABEL {
						target := uint64(operand.Immediate) // slid address
						if _, exists := result[target]; !exists {
							// Unslide target for symbol lookup (macho has unslid addresses)
							lookupAddr := target
							if slide > 0 && target >= slide {
								lookupAddr = target - slide
							}
							if syms, err := lookup.FindAddressSymbols(lookupAddr); err == nil && len(syms) > 0 {
								// Store with slid key for lookup in formatPeekDisassembly
								result[target] = syms[0].Name
							}
						}
						break
					}
				}
			}
		}
	}

	if len(result) == 0 {
		return nil
	}
	return result
}

// formatPeekDisassembly formats the peek bytes as disassembly output.
// peekFrameIdx is the index of the frame instruction within peekBytes (in instructions, not bytes).
// peekAddr is the start address of peekBytes.
// slide is used to adjust displayed addresses if unslid is true.
// customSlide is added to kernel frame addresses for live debugging (--kc-slide flag).
// dscSlide is added to DSC frame addresses for live debugging (--dsc-slide flag).
// isDSCFrame indicates if this is a dyld_shared_cache frame (Source == "SharedCache" or "SharedCacheLibrary").
// peekSymbols optionally maps addresses to symbol names for enriching branch targets.
// doMangle indicates whether to demangle symbol names.
//
// NOTE: For kernel frames, peekAddr is already an unslid address (BinaryImage.Base + ImageOffset).
// For user frames, peekAddr is a slid address. The unslid flag should only affect user frames.
func formatPeekDisassembly(peekBytes []byte, peekAddr uint64, peekFrameIdx int, slide, customSlide, dscSlide uint64, isDSCFrame, unslid bool, peekSymbols map[uint64]string, doMangle bool) string {
	if len(peekBytes) == 0 {
		return ""
	}

	instructions, err := disassemble.GetInstructions(peekAddr, peekBytes)
	if err != nil {
		return ""
	}

	// Detect if this is a kernel frame by checking if peekAddr is in kernel address space.
	// Kernel addresses are in high memory (0xfffffff0_00000000 and above).
	isKernelFrame := peekAddr >= 0xfffffff000000000

	var out strings.Builder
	instrIdx := 0
	for _, block := range instructions.Blocks() {
		for _, instr := range block {
			// Determine display address
			displayAddr := instr.Address

			if isKernelFrame && customSlide != 0 {
				// Apply custom slide to kernel frames for live debugging
				displayAddr += customSlide
			} else if isDSCFrame && dscSlide != 0 {
				// Apply DSC slide to shared cache frames for live debugging
				displayAddr += dscSlide
			} else if !isKernelFrame && unslid && slide != 0 && displayAddr >= slide {
				// Only apply unslide logic to user frames (not kernel frames)
				displayAddr -= slide
			}

			// Mark the frame instruction with --> using the frame index
			pad := "          "
			if instrIdx == peekFrameIdx {
				pad = "      --> "
			}

			opStr := strings.TrimSpace(strings.TrimPrefix(instr.String(), instr.Operation.String()))

			// Enrich branch instructions (B/BL) with symbol names if available
			comment := ""
			if (instr.Operation == disassemble.ARM64_BL || instr.Operation == disassemble.ARM64_B) && len(peekSymbols) > 0 {
				for _, operand := range instr.Operands {
					if operand.Class == disassemble.LABEL {
						target := uint64(operand.Immediate)
						if symName, ok := peekSymbols[target]; ok {
							display := symName
							if doMangle {
								display = demangle.Do(symName, false, false)
							}
							comment = fmt.Sprintf(" ; %s", display)
						}
						break
					}
				}
			}

			out.WriteString(fmt.Sprintf("%s%s:  %s   %s %s%s\n",
				pad,
				colorAddr("%#08x", displayAddr),
				disassemble.GetOpCodeByteString(instr.Raw),
				colorImage("%-7s", instr.Operation),
				disass.ColorOperands(opStr),
				colorField(comment),
			))
			instrIdx++
		}
	}
	return out.String()
}

// isDSCFrame returns true if the frame is from dyld_shared_cache (Source == "SharedCache" or "SharedCacheLibrary").
func (i *Ips) isDSCFrame(frame PanicFrame) bool {
	if int(frame.ImageIndex) < len(i.Payload.BinaryImages) {
		src := i.Payload.BinaryImages[frame.ImageIndex].Source
		return src == "SharedCache" || src == "SharedCacheLibrary"
	}
	return false
}

// panicFrameAddr computes the display address for a panic frame.
// After Symbolicate210: ImageOffset already has Base added:
//   - User frames: Base is slid, so ImageOffset is the slid runtime address
//   - Kernel frames: Base + raw offset = unslid address (kernel frames are already KASLR-unslid in crashlog JSON)
//
// The --unslide flag subtracts the slide to show unslid addresses (only affects user frames).
// The --slide flag adds a custom KASLR slide to kernel frames for live debugging.
// The --dsc-slide flag adds a custom slide to dyld_shared_cache frames for live debugging.
// Returns: (address, slide, wasSlid)
func (i *Ips) panicFrameAddr(frame PanicFrame) (addr, slide uint64, wasSlid bool) {
	// After symbolication, ImageOffset = BinaryImage.Base + raw offset from JSON
	// (Symbolicate210 does: frame.ImageOffset += BinaryImage.Base)
	addr = frame.ImageOffset

	// Get slide - frame.Slide is set during Symbolicate210 from BinaryImage.Slide
	if frame.Slide != 0 {
		slide = frame.Slide
	} else if int(frame.ImageIndex) < len(i.Payload.BinaryImages) {
		slide = i.Payload.BinaryImages[frame.ImageIndex].Slide
	}

	// Detect frame source type
	var isKernel, isDSC bool
	if int(frame.ImageIndex) < len(i.Payload.BinaryImages) {
		src := i.Payload.BinaryImages[frame.ImageIndex].Source
		switch src {
		case "Kernel", "KernelCache", "KernelTextExec":
			isKernel = true
		case "SharedCache", "SharedCacheLibrary":
			isDSC = true
		}
	}

	// Apply custom slides for live debugging:
	// - Kernel frames are stored unslid, so we ADD the custom slide to get runtime addresses
	// - DSC frames are stored with the static cache address, ADD custom slide to get runtime addresses
	if isKernel && i.Config.KernelSlide != 0 {
		addr += i.Config.KernelSlide
		slide = i.Config.KernelSlide
		wasSlid = true
	} else if isDSC && i.Config.DSCSlide != 0 {
		addr += i.Config.DSCSlide
		slide = i.Config.DSCSlide
		wasSlid = true
	} else if i.Config.Unslid {
		// Unslide user frames (kernel frames are already unslid, so skip them)
		if !isKernel && slide != 0 && addr >= slide {
			addr -= slide
		}
	}
	return addr, slide, wasSlid
}

func (i *Ips) Symbolicate210(ipswPath string) (err error) {

	i.Payload.panic210, err = parsePanicString210(i.Payload.PanicString)
	if err != nil {
		return fmt.Errorf("failed to parse panic string: %w", err)
	}

	total := len(i.Payload.BinaryImages)

	// add default binary image names
	for idx, img := range i.Payload.BinaryImages {
		switch img.Source {
		case "Absolute":
			i.Payload.BinaryImages[idx].Name = "absolute"
			total--
		case "Kernel":
			i.Payload.BinaryImages[idx].Name = "kernel"
			if i.Payload.panic210 != nil && i.Payload.panic210.KernelSlide != nil {
				i.Payload.BinaryImages[idx].Slide = i.Payload.panic210.KernelSlide.Value.(uint64)
			}
			total--
		case "KernelCache":
			i.Payload.BinaryImages[idx].Name = "kernelcache"
			if i.Payload.panic210 != nil {
				switch {
				case i.Payload.panic210.KernelCacheSlide != nil:
					i.Payload.BinaryImages[idx].Slide = i.Payload.panic210.KernelCacheSlide.Value.(uint64)
				case i.Payload.panic210.KernelSlide != nil:
					i.Payload.BinaryImages[idx].Slide = i.Payload.panic210.KernelSlide.Value.(uint64)
				}
			}
			total--
		case "KernelTextExec":
			i.Payload.BinaryImages[idx].Name = "kernelcache (__TEXT_EXEC)"
			if i.Payload.panic210 != nil && i.Payload.panic210.KernelTextExecSlide != nil {
				i.Payload.BinaryImages[idx].Slide = i.Payload.panic210.KernelTextExecSlide.Value.(uint64)
			}
			total--
		case "SharedCache":
			i.Payload.BinaryImages[idx].Name = "dyld_shared_cache"
			total--
		case "SharedCacheLibrary":
			i.Payload.BinaryImages[idx].Name = "dyld_shared_cache (library)"
			total--
		}
	}

	machoFuncMap := make(map[string][]types.Function)
	uuidFuncMap := make(map[string][]types.Function)

	/* SYMBOLICATE KERNELCACHE */
	var kc *macho.File
	{
		// If crashlog has no device identifier, prompt user to select from available devices
		device := i.Payload.Product
		log.WithField("device", device).Debug("Looking for kernelcache matching crashlog device")
		if device == "" {
			ipswInfo, err := info.Parse(ipswPath)
			if err != nil {
				return fmt.Errorf("crashlog has no device identifier and failed to parse IPSW info: %w", err)
			}
			var devices []string
			for _, dtree := range ipswInfo.DeviceTrees {
				if dt, err := dtree.Summary(); err == nil {
					devices = append(devices, dt.ProductType)
				}
			}
			if len(devices) == 0 {
				return fmt.Errorf("crashlog has no device identifier and no devices found in IPSW")
			}
			sort.Strings(devices)
			if len(devices) == 1 {
				device = devices[0]
				log.Warnf("crashlog has no device identifier; using only available device: %s", device)
			} else {
				var choice string
				prompt := &survey.Select{
					Message:  "Crashlog has no device identifier. Select target device:",
					Options:  devices,
					PageSize: 15,
				}
				if err := survey.AskOne(prompt, &choice); err != nil {
					if err == terminal.InterruptErr {
						return fmt.Errorf("user cancelled device selection")
					}
					return fmt.Errorf("failed to select device: %w", err)
				}
				device = choice
			}
		}

		out, err := extract.Kernelcache(&extract.Config{
			IPSW:         ipswPath,
			KernelDevice: device,
			Output:       os.TempDir(),
		})
		if err != nil {
			return fmt.Errorf("failed to extract kernelcache: %w", err)
		}
		if len(out) == 0 {
			return fmt.Errorf("no kernelcache found for device %s in IPSW (multi-device IPSW may not contain this device)", device)
		}
		// Log which kernelcache(s) were found for the device
		for k := range out {
			log.WithFields(log.Fields{
				"device":      device,
				"kernelcache": filepath.Base(k),
			}).Debug("Found kernelcache for device")
		}
		defer func() {
			for k := range out {
				os.Remove(k)
			}
		}()

		// Collect all kernel-related UUIDs from crashlog for validation
		// kc.UUID() returns the LC_UUID of the kernelcache container
		type kernelUUIDInfo struct {
			name string
			uuid string
		}
		var crashlogKernelUUIDs []kernelUUIDInfo
		if i.Payload.panic210 != nil {
			if i.Payload.panic210.DebugHdrKernelCacheUUID != nil {
				crashlogKernelUUIDs = append(crashlogKernelUUIDs, kernelUUIDInfo{
					name: "Debug Header KernelCache UUID",
					uuid: i.Payload.panic210.DebugHdrKernelCacheUUID.Value.(string),
				})
			}
			if i.Payload.panic210.FilesetKernelCacheUUID != nil {
				crashlogKernelUUIDs = append(crashlogKernelUUIDs, kernelUUIDInfo{
					name: "Fileset KernelCache UUID",
					uuid: i.Payload.panic210.FilesetKernelCacheUUID.Value.(string),
				})
			}
			if i.Payload.panic210.KernelCacheUUID != nil {
				crashlogKernelUUIDs = append(crashlogKernelUUIDs, kernelUUIDInfo{
					name: "KernelCache UUID",
					uuid: i.Payload.panic210.KernelCacheUUID.Value.(string),
				})
			}
			if i.Payload.panic210.KernelUUID != nil {
				crashlogKernelUUIDs = append(crashlogKernelUUIDs, kernelUUIDInfo{
					name: "Kernel UUID",
					uuid: i.Payload.panic210.KernelUUID.Value.(string),
				})
			}
		}

		for k := range out {
			smap := signature.NewSymbolMap()
			if i.Config.SignaturesDir != "" {
				// parse signatures
				sigs, err := signature.Parse(i.Config.SignaturesDir)
				if err != nil {
					return fmt.Errorf("failed to parse signatures: %v", err)
				}
				// symbolicate kernelcache (quiet=true suppresses per-file logs, shows progress bar)
				log.WithField("kernelcache", filepath.Base(k)).Info("Symbolicating...")
				if err := smap.Symbolicate(k, sigs, !i.Config.Verbose); err != nil {
					return fmt.Errorf("failed to symbolicate kernelcache: %v", err)
				}
				// Store symbols for IDA script generation
				i.KernelSymbols = smap
			}

			kc, err = macho.Open(k)
			if err != nil {
				return fmt.Errorf("failed to open kernelcache: %v", err)
			}
			defer kc.Close()

			// Validate kernelcache UUID matches any of the crashlog's kernel UUIDs
			if len(crashlogKernelUUIDs) > 0 {
				if kcUUID := kc.UUID(); kcUUID != nil {
					// Log the IPSW kernelcache UUID we extracted
					log.WithField("uuid", kcUUID.UUID.String()).Info("IPSW kernelcache UUID")

					// Log all crashlog kernel UUIDs for comparison
					for _, info := range crashlogKernelUUIDs {
						log.WithFields(log.Fields{
							"field": info.name,
							"uuid":  info.uuid,
						}).Debug("Crashlog kernel UUID")
					}

					// Normalize IPSW UUID: uppercase and no dashes for comparison
					actualUUID := strings.ToUpper(strings.ReplaceAll(kcUUID.UUID.String(), "-", ""))

					// Check against all kernel-related UUIDs from crashlog
					matched := false
					var matchedField string
					for _, info := range crashlogKernelUUIDs {
						expectedUUID := strings.ToUpper(strings.ReplaceAll(info.uuid, "-", ""))
						if actualUUID == expectedUUID {
							matched = true
							matchedField = info.name
							break
						}
					}

					if matched {
						log.WithFields(log.Fields{
							"field": matchedField,
							"uuid":  kcUUID.UUID.String(),
						}).Info("Kernelcache UUID validated")
					} else {
						// Log all the UUIDs we tried to match against
						var uuidList []string
						for _, info := range crashlogKernelUUIDs {
							uuidList = append(uuidList, fmt.Sprintf("%s=%s", info.name, info.uuid))
						}
						log.WithFields(log.Fields{
							"ipsw_uuid":      kcUUID.UUID.String(),
							"crashlog_uuids": strings.Join(uuidList, ", "),
						}).Warn("Kernelcache UUID mismatch: IPSW UUID doesn't match any crashlog kernel UUID")
					}
				}
			} else {
				log.Debug("No kernelcache UUID in crashlog, skipping validation")
			}

			if kc.FileTOC.FileHeader.Type == types.MH_FILESET {
				for _, fe := range kc.FileSets() {
					mfe, err := kc.GetFileSetFileByName(fe.EntryID)
					if err != nil {
						return fmt.Errorf("failed to parse entry %s: %v", fe.EntryID, err)
					}
					for _, fn := range mfe.GetFunctions() {
						if syms, err := mfe.FindAddressSymbols(fn.StartAddr); err == nil {
							for _, sym := range syms {
								fn.Name = sym.Name
							}
						} else {
							if sym, ok := smap[fn.StartAddr]; ok {
								fn.Name = sym
							}
						}
						if fn.Name == "" {
							fn.Name = fmt.Sprintf("func_%x", fn.StartAddr)
						}
						machoFuncMap["kernelcache"] = append(machoFuncMap["kernelcache"], fn)
						// Also map under "kernel" for Source=Kernel frames
						machoFuncMap["kernel"] = append(machoFuncMap["kernel"], fn)
						// Also map under "kernelcache (__TEXT_EXEC)" for Source=KernelTextExec frames
						machoFuncMap["kernelcache (__TEXT_EXEC)"] = append(machoFuncMap["kernelcache (__TEXT_EXEC)"], fn)
					}
				}
			} else { // non-fileset kernelcache
				for _, fn := range kc.GetFunctions() {
					if syms, err := kc.FindAddressSymbols(fn.StartAddr); err == nil {
						for _, sym := range syms {
							fn.Name = sym.Name
						}
					} else {
						if sym, ok := smap[fn.StartAddr]; ok {
							fn.Name = sym
						}
						if fn.Name == "" {
							fn.Name = fmt.Sprintf("func_%x", fn.StartAddr)
						}
					}
					machoFuncMap["kernelcache"] = append(machoFuncMap["kernelcache"], fn)
					// Also map under "kernel" for Source=Kernel frames
					machoFuncMap["kernel"] = append(machoFuncMap["kernel"], fn)
					// Also map under "kernelcache (__TEXT_EXEC)" for Source=KernelTextExec frames
					machoFuncMap["kernelcache (__TEXT_EXEC)"] = append(machoFuncMap["kernelcache (__TEXT_EXEC)"], fn)
				}
			}
		}
	}

	/* SYMBOLICATE EXTRA MACHOS */
	if i.Config.ExtrasDir != "" {
		if err := search.ForEachMacho(i.Config.ExtrasDir, func(path string, m *macho.File) error {
			for idx, img := range i.Payload.BinaryImages {
				if m.UUID() != nil && strings.EqualFold(img.UUID, m.UUID().UUID.String()) {
					i.Payload.BinaryImages[idx].Path = path
					i.Payload.BinaryImages[idx].Name = path
					// i.Payload.BinaryImages[idx].Name = filepath.Base(path)
					i.Payload.BinaryImages[idx].Slide = i.Payload.BinaryImages[idx].Base - m.GetBaseAddress()
					for _, fn := range m.GetFunctions() {
						if syms, err := m.FindAddressSymbols(fn.StartAddr); err == nil {
							for _, sym := range syms {
								fn.Name = sym.Name
							}
							fn.StartAddr += i.Payload.BinaryImages[idx].Slide
							fn.EndAddr += i.Payload.BinaryImages[idx].Slide
							machoFuncMap[i.Payload.BinaryImages[idx].Name] = append(machoFuncMap[i.Payload.BinaryImages[idx].Name], fn)
							uuidFuncMap[strings.ToUpper(img.UUID)] = append(uuidFuncMap[strings.ToUpper(img.UUID)], fn)
						} else {
							fn.StartAddr += i.Payload.BinaryImages[idx].Slide
							fn.EndAddr += i.Payload.BinaryImages[idx].Slide
							fn.Name = fmt.Sprintf("func_%x", fn.StartAddr)
							machoFuncMap[i.Payload.BinaryImages[idx].Name] = append(machoFuncMap[i.Payload.BinaryImages[idx].Name], fn)
							uuidFuncMap[strings.ToUpper(img.UUID)] = append(uuidFuncMap[strings.ToUpper(img.UUID)], fn)
						}
					}
					total--
				}
			}
			return nil
		}); err != nil {
			if !errors.Is(err, ErrDone) {
				return fmt.Errorf("failed to symbolicate: %w", err)
			}
		}
	}

	/* SYMBOLICATE FILESYSTEM MACHOS */
	if err := search.ForEachMachoInIPSW(ipswPath, i.Config.PemDB, func(path string, m *macho.File) error {
		if total == 0 {
			return ErrDone // break
		}
		for idx, img := range i.Payload.BinaryImages {
			if m.UUID() != nil && strings.EqualFold(img.UUID, m.UUID().UUID.String()) {
				i.Payload.BinaryImages[idx].Path = path
				i.Payload.BinaryImages[idx].Name = path
				// i.Payload.BinaryImages[idx].Name = filepath.Base(path)
				i.Payload.BinaryImages[idx].Slide = i.Payload.BinaryImages[idx].Base - m.GetBaseAddress()
				// Read peek bytes for panicked thread user frames from this binary (--peek flag)
				if i.Config.Peek && i.Payload.panic210 != nil {
					panicPID := i.Payload.panic210.PanickedTask.PID
					panicTID := i.Payload.panic210.PanickedThread.TID
					if proc, ok := i.Payload.ProcessByPid[panicPID]; ok {
						if thread, ok := proc.ThreadByID[panicTID]; ok {
							for frameIdx := range thread.UserFrames {
								frame := &i.Payload.ProcessByPid[panicPID].ThreadByID[panicTID].UserFrames[frameIdx]
								if frame.ImageIndex == uint64(idx) {
									// Compute the VM address relative to MachO base (not runtime base)
									// frame.ImageOffset is raw offset within image
									// m.GetBaseAddress() is MachO's preferred load address
									vmAddr := m.GetBaseAddress() + frame.ImageOffset
									// Get function boundaries for boundary checking
									var funcStart, funcEnd uint64
									if fn, err := m.GetFunctionForVMAddr(vmAddr); err == nil {
										funcStart = fn.StartAddr
										funcEnd = fn.EndAddr
									}
									if peekBytes, startAddr, frameIdx := readPeekBytes(m, vmAddr, i.Config.PeekCount, funcStart, funcEnd); peekBytes != nil {
										frame.PeekBytes = peekBytes
										// Store the runtime (slid) address for display
										slide := i.Payload.BinaryImages[idx].Slide
										slidAddr := startAddr + slide
										frame.PeekAddr = slidAddr
										frame.PeekFrameIdx = frameIdx
										// Extract symbols for branch targets in peek bytes
										// Use slid address so keys match what formatPeekDisassembly will look up
										frame.PeekSymbols = extractPeekSymbols(peekBytes, slidAddr, slide, m)
									}
								}
							}
						}
					}
				}
				for _, fn := range m.GetFunctions() {
					if syms, err := m.FindAddressSymbols(fn.StartAddr); err == nil {
						for _, sym := range syms {
							fn.Name = sym.Name
						}
						fn.StartAddr += i.Payload.BinaryImages[idx].Slide
						fn.EndAddr += i.Payload.BinaryImages[idx].Slide
						machoFuncMap[i.Payload.BinaryImages[idx].Name] = append(machoFuncMap[i.Payload.BinaryImages[idx].Name], fn)
						uuidFuncMap[strings.ToUpper(img.UUID)] = append(uuidFuncMap[strings.ToUpper(img.UUID)], fn)
					} else {
						fn.StartAddr += i.Payload.BinaryImages[idx].Slide
						fn.EndAddr += i.Payload.BinaryImages[idx].Slide
						fn.Name = fmt.Sprintf("func_%x", fn.StartAddr)
						machoFuncMap[i.Payload.BinaryImages[idx].Name] = append(machoFuncMap[i.Payload.BinaryImages[idx].Name], fn)
						uuidFuncMap[strings.ToUpper(img.UUID)] = append(uuidFuncMap[strings.ToUpper(img.UUID)], fn)
					}
				}
				total--
			}
		}
		return nil
	}); err != nil {
		if !errors.Is(err, ErrDone) {
			return fmt.Errorf("failed to symbolicate: %w", err)
		}
	}

	// print any binary images that are missing names
	// for idx, img := range i.Payload.BinaryImages {
	// 	if len(img.Name) == 0 {
	// 		fmt.Printf("idx: %d - %v\n", idx, img)
	// 	}
	// }

	ctx, fs, err := dsc.OpenFromIPSW(ipswPath, i.Config.PemDB, false, true)
	if err != nil {
		return fmt.Errorf("failed to open DSC from IPSW: %w", err)
	}
	defer func() {
		for _, f := range fs {
			f.Close()
		}
		ctx.Unmount()
	}()

	for pid, proc := range i.Payload.ProcessByPid {
		for tid, thread := range proc.ThreadByID {
			for idx, frame := range thread.UserFrames {
				i.Payload.ProcessByPid[pid].ThreadByID[tid].UserFrames[idx].ImageOffset += i.Payload.BinaryImages[frame.ImageIndex].Base
				if i.Payload.BinaryImages[frame.ImageIndex].Slide != 0 {
					i.Payload.ProcessByPid[pid].ThreadByID[tid].UserFrames[idx].Slide = i.Payload.BinaryImages[frame.ImageIndex].Slide
				}
				if len(i.Payload.BinaryImages[frame.ImageIndex].Name) > 0 {
					i.Payload.ProcessByPid[pid].ThreadByID[tid].UserFrames[idx].ImageName = i.Payload.BinaryImages[frame.ImageIndex].Name
				} else {
					if strings.HasPrefix(i.Payload.ProcessByPid[pid].ThreadByID[tid].UserFrames[idx].ImageName, "image_") {
						i.Payload.ProcessByPid[pid].ThreadByID[tid].UserFrames[idx].ImageName += fmt.Sprintf(" (probably %s)", proc.Name)
					}
				}
				if i.Payload.ProcessByPid[pid].ThreadByID[tid].UserFrames[idx].ImageName == "absolute" {
					continue // skip absolute
				} else if i.Payload.ProcessByPid[pid].ThreadByID[tid].UserFrames[idx].ImageName == "dyld_shared_cache" {
					for _, f := range fs {
						if !strings.EqualFold(i.Payload.BinaryImages[frame.ImageIndex].UUID, f.UUID.String()) {
							continue // skip to next DSC
						}
						if f.Headers[f.UUID].SharedRegionStart != i.Payload.BinaryImages[frame.ImageIndex].Base {
							i.Payload.ProcessByPid[pid].ThreadByID[tid].UserFrames[idx].Slide = i.Payload.BinaryImages[frame.ImageIndex].Base - f.Headers[f.UUID].SharedRegionStart
						}
						// lookup symbol in DSC dylib
						if img, err := f.GetImageContainingVMAddr(i.Payload.ProcessByPid[pid].ThreadByID[tid].UserFrames[idx].ImageOffset); err == nil {
							i.Payload.ProcessByPid[pid].ThreadByID[tid].UserFrames[idx].ImageName = filepath.Base(img.Name)
							img.ParsePublicSymbols(false)
							img.ParseLocalSymbols(false)
							m, err := img.GetMacho()
							if err != nil {
								return fmt.Errorf("failed to get macho from image: %w", err)
							}
							if fn, err := m.GetFunctionForVMAddr(i.Payload.ProcessByPid[pid].ThreadByID[tid].UserFrames[idx].ImageOffset); err == nil {
								if sym, ok := f.AddressToSymbol[fn.StartAddr]; ok {
									i.Payload.ProcessByPid[pid].ThreadByID[tid].UserFrames[idx].Symbol = demangleSym(i.Config.Demangle, sym)
									if i.Payload.ProcessByPid[pid].ThreadByID[tid].UserFrames[idx].ImageOffset-fn.StartAddr != 0 {
										i.Payload.ProcessByPid[pid].ThreadByID[tid].UserFrames[idx].SymbolLocation = i.Payload.ProcessByPid[pid].ThreadByID[tid].UserFrames[idx].ImageOffset - fn.StartAddr
									}
								} else {
									i.Payload.ProcessByPid[pid].ThreadByID[tid].UserFrames[idx].Symbol = fmt.Sprintf("func_%x", fn.StartAddr)
								}
							}
						}
					}
				} else { // "Process"
					// lookup symbol in MachO symbol map (by name, then fall back to UUID)
					funcs, ok := machoFuncMap[i.Payload.ProcessByPid[pid].ThreadByID[tid].UserFrames[idx].ImageName]
					if !ok {
						uuid := strings.ToUpper(i.Payload.BinaryImages[frame.ImageIndex].UUID)
						funcs, ok = uuidFuncMap[uuid]
					}
					if ok {
						found := false
						for _, fn := range funcs {
							if fn.StartAddr <= i.Payload.ProcessByPid[pid].ThreadByID[tid].UserFrames[idx].ImageOffset && i.Payload.ProcessByPid[pid].ThreadByID[tid].UserFrames[idx].ImageOffset < fn.EndAddr {
								found = true
								i.Payload.ProcessByPid[pid].ThreadByID[tid].UserFrames[idx].Symbol = demangleSym(i.Config.Demangle, fn.Name)
								if i.Payload.ProcessByPid[pid].ThreadByID[tid].UserFrames[idx].ImageOffset-fn.StartAddr != 0 {
									i.Payload.ProcessByPid[pid].ThreadByID[tid].UserFrames[idx].SymbolLocation = i.Payload.ProcessByPid[pid].ThreadByID[tid].UserFrames[idx].ImageOffset - fn.StartAddr
								}
								break
							}
						}
						if !found {
							// sometimes a frame will report using `dyld` but the offset is not in any function or in the binary image (e.g. in memory macho)
							if i.Payload.ProcessByPid[pid].ThreadByID[tid].UserFrames[idx].ImageName == "/usr/lib/dyld" {
								i.Payload.ProcessByPid[pid].ThreadByID[tid].UserFrames[idx].ImageName += " (??? in memory macho)"
							}
							log.WithFields(log.Fields{
								"proc":   fmt.Sprintf("%s [%d]", proc.Name, pid),
								"thread": tid,
								"frame":  idx,
								"img":    i.Payload.ProcessByPid[pid].ThreadByID[tid].UserFrames[idx].ImageName,
							}).Debugf("failed to find function for process offset %#x", i.Payload.ProcessByPid[pid].ThreadByID[tid].UserFrames[idx].ImageOffset)
						}
					} else {
						log.WithFields(log.Fields{
							"proc":   fmt.Sprintf("%s [%d]", proc.Name, pid),
							"thread": tid,
							"frame":  idx,
							"img":    i.Payload.ProcessByPid[pid].ThreadByID[tid].UserFrames[idx].ImageName,
						}).Debugf("failed to find function for process offset %#x", i.Payload.ProcessByPid[pid].ThreadByID[tid].UserFrames[idx].ImageOffset)
					}
				}
			}
			/* KernelFrames */
			for idx, frame := range thread.KernelFrames {
				i.Payload.ProcessByPid[pid].ThreadByID[tid].KernelFrames[idx].ImageOffset += i.Payload.BinaryImages[frame.ImageIndex].Base
				if i.Payload.BinaryImages[frame.ImageIndex].Slide != 0 {
					i.Payload.ProcessByPid[pid].ThreadByID[tid].KernelFrames[idx].Slide = i.Payload.BinaryImages[frame.ImageIndex].Slide
				}
				if len(i.Payload.BinaryImages[frame.ImageIndex].Name) > 0 {
					i.Payload.ProcessByPid[pid].ThreadByID[tid].KernelFrames[idx].ImageName = i.Payload.BinaryImages[frame.ImageIndex].Name
				} else {
					if strings.HasPrefix(i.Payload.ProcessByPid[pid].ThreadByID[tid].KernelFrames[idx].ImageName, "image_") {
						i.Payload.ProcessByPid[pid].ThreadByID[tid].KernelFrames[idx].ImageName += " (maybe a kext)"
					}
				}
				if i.Payload.ProcessByPid[pid].ThreadByID[tid].KernelFrames[idx].ImageName == "absolute" {
					continue // skip absolute
				} else if funcs, ok := machoFuncMap[i.Payload.ProcessByPid[pid].ThreadByID[tid].KernelFrames[idx].ImageName]; ok {
					found := false
					for _, fn := range funcs {
						if fn.StartAddr <= i.Payload.ProcessByPid[pid].ThreadByID[tid].KernelFrames[idx].ImageOffset &&
							i.Payload.ProcessByPid[pid].ThreadByID[tid].KernelFrames[idx].ImageOffset < fn.EndAddr {
							found = true
							i.Payload.ProcessByPid[pid].ThreadByID[tid].KernelFrames[idx].Symbol = demangleSym(i.Config.Demangle, fn.Name)
							if i.Payload.ProcessByPid[pid].ThreadByID[tid].KernelFrames[idx].ImageOffset-fn.StartAddr != 0 {
								i.Payload.ProcessByPid[pid].ThreadByID[tid].KernelFrames[idx].SymbolLocation = i.Payload.ProcessByPid[pid].ThreadByID[tid].KernelFrames[idx].ImageOffset - fn.StartAddr
							}
							break
						}
					}
					if !found {
						// if i.Payload.ProcessByPid[pid].ThreadByID[tid].KernelFrames[idx].ImageName == "??" {
						// 	i.Payload.ProcessByPid[pid].ThreadByID[tid].KernelFrames[idx].ImageName += " (??? maybe kext?)"
						// }
						if seg := kc.FindSegmentForVMAddr(i.Payload.ProcessByPid[pid].ThreadByID[tid].KernelFrames[idx].ImageOffset); seg != nil {
							i.Payload.ProcessByPid[pid].ThreadByID[tid].KernelFrames[idx].Symbol = seg.Name
							if sec := kc.FindSectionForVMAddr(i.Payload.ProcessByPid[pid].ThreadByID[tid].KernelFrames[idx].ImageOffset); sec != nil {
								i.Payload.ProcessByPid[pid].ThreadByID[tid].KernelFrames[idx].Symbol += "." + sec.Name
							}
						} else {
							i.Payload.ProcessByPid[pid].ThreadByID[tid].KernelFrames[idx].Symbol = "???"
							log.WithFields(log.Fields{
								"proc":   fmt.Sprintf("%s [%d]", proc.Name, pid),
								"thread": tid,
								"frame":  idx,
								"img":    i.Payload.ProcessByPid[pid].ThreadByID[tid].KernelFrames[idx].ImageName,
							}).Debugf("failed to find function for process offset %#x", i.Payload.ProcessByPid[pid].ThreadByID[tid].KernelFrames[idx].ImageOffset)
						}
					}
				} else {
					log.WithFields(log.Fields{
						"proc":   fmt.Sprintf("%s [%d]", proc.Name, pid),
						"thread": tid,
						"frame":  idx,
						"img":    i.Payload.ProcessByPid[pid].ThreadByID[tid].KernelFrames[idx].ImageName,
						"offset": fmt.Sprintf("%#x", i.Payload.ProcessByPid[pid].ThreadByID[tid].KernelFrames[idx].ImageOffset),
					}).Errorf("unexpected image")
				}
			}

			// Read peek bytes for panicked thread frames (--peek flag)
			if i.Config.Peek && i.Payload.panic210 != nil &&
				pid == i.Payload.panic210.PanickedTask.PID &&
				tid == i.Payload.panic210.PanickedThread.TID {
				// cache already-opened machos so we don't reopen for each frame
				machoCache := make(map[int]*macho.File)
				defer func() {
					for _, m := range machoCache {
						m.Close()
					}
				}()

				// Read peek bytes for kernel frames from kernelcache
				for idx := range i.Payload.ProcessByPid[pid].ThreadByID[tid].KernelFrames {
					frame := &i.Payload.ProcessByPid[pid].ThreadByID[tid].KernelFrames[idx]
					if frame.ImageName == "absolute" {
						continue
					}
					if frame.ImageOffset > 0 {
						// Get function boundaries for boundary checking
						var funcStart, funcEnd uint64
						if fn, err := kc.GetFunctionForVMAddr(frame.ImageOffset); err == nil {
							funcStart = fn.StartAddr
							funcEnd = fn.EndAddr
						}
						// Use the runtime (slid) address for reading; kc segments are already in slid VM space.
						if peekBytes, startAddr, frameIdx := readPeekBytes(kc, frame.ImageOffset, i.Config.PeekCount, funcStart, funcEnd); peekBytes != nil {
							frame.PeekBytes = peekBytes
							frame.PeekAddr = startAddr
							frame.PeekFrameIdx = frameIdx
							// Extract symbols for branch targets in peek bytes (kernel has no slide)
							frame.PeekSymbols = extractPeekSymbols(peekBytes, startAddr, 0, kc)
						}
					}
				}
				// Read peek bytes for user frames from DSC (process binaries already handled during ForEachMachoInIPSW)
				for idx := range i.Payload.ProcessByPid[pid].ThreadByID[tid].UserFrames {
					frame := &i.Payload.ProcessByPid[pid].ThreadByID[tid].UserFrames[idx]
					if frame.ImageName == "absolute" || len(frame.PeekBytes) > 0 {
						continue // skip absolute or frames already populated from filesystem
					}
					if frame.ImageOffset > 0 {
						frameSlide := frame.Slide
						if frameSlide == 0 && int(frame.ImageIndex) < len(i.Payload.BinaryImages) {
							frameSlide = i.Payload.BinaryImages[frame.ImageIndex].Slide
						}
						unslidAddr := frame.ImageOffset
						if frameSlide != 0 && unslidAddr >= frameSlide {
							unslidAddr -= frameSlide
						}
						// 1) Try using a located MachO on disk (extras/IPSW/symbol server)
						if bi := i.Payload.BinaryImages[frame.ImageIndex]; len(bi.Path) > 0 {
							if m, ok := machoCache[int(frame.ImageIndex)]; ok {
								var funcStart, funcEnd uint64
								if fn, err := m.GetFunctionForVMAddr(unslidAddr); err == nil {
									funcStart = fn.StartAddr
									funcEnd = fn.EndAddr
								}
								if peekBytes, startAddr, peekFrameIdx := readPeekBytes(m, unslidAddr, i.Config.PeekCount, funcStart, funcEnd); peekBytes != nil {
									frame.PeekBytes = peekBytes
									slidAddr := startAddr + frameSlide
									frame.PeekAddr = slidAddr
									frame.PeekFrameIdx = peekFrameIdx
									// Extract symbols for branch targets in peek bytes
									frame.PeekSymbols = extractPeekSymbols(peekBytes, slidAddr, frameSlide, m)
									continue
								}
							} else if m, err := macho.Open(bi.Path); err == nil {
								machoCache[int(frame.ImageIndex)] = m
								var funcStart, funcEnd uint64
								if fn, err := m.GetFunctionForVMAddr(unslidAddr); err == nil {
									funcStart = fn.StartAddr
									funcEnd = fn.EndAddr
								}
								if peekBytes, startAddr, peekFrameIdx := readPeekBytes(m, unslidAddr, i.Config.PeekCount, funcStart, funcEnd); peekBytes != nil {
									frame.PeekBytes = peekBytes
									slidAddr := startAddr + frameSlide
									frame.PeekAddr = slidAddr
									frame.PeekFrameIdx = peekFrameIdx
									// Extract symbols for branch targets in peek bytes
									frame.PeekSymbols = extractPeekSymbols(peekBytes, slidAddr, frameSlide, m)
									continue
								}
							} else {
								log.WithError(err).Debugf("failed to open macho for peek: %s", bi.Path)
							}
						}

						// 2) Try reading from DSC as a fallback
						for _, f := range fs {
							if img, err := f.GetImageContainingVMAddr(frame.ImageOffset); err == nil {
								if m, err := img.GetMacho(); err == nil {
									unslidAddr := frame.ImageOffset
									if frameSlide != 0 && unslidAddr >= frameSlide {
										unslidAddr -= frameSlide
									}
									var funcStart, funcEnd uint64
									if fn, err := m.GetFunctionForVMAddr(unslidAddr); err == nil {
										funcStart = fn.StartAddr
										funcEnd = fn.EndAddr
									}
									if peekBytes, startAddr, peekFrameIdx := readPeekBytes(m, unslidAddr, i.Config.PeekCount, funcStart, funcEnd); peekBytes != nil {
										frame.PeekBytes = peekBytes
										slidAddr := startAddr + frameSlide
										frame.PeekAddr = slidAddr
										frame.PeekFrameIdx = peekFrameIdx
										// Extract symbols for branch targets in peek bytes
										frame.PeekSymbols = extractPeekSymbols(peekBytes, slidAddr, frameSlide, m)
									}
								}
								break
							}
						}
					}
				}
			}
		}
	}

	// Generate IDA Python scripts if requested
	if i.Config.IDAScript {
		if err := i.generateIDAScripts(); err != nil {
			return fmt.Errorf("failed to generate IDA scripts: %w", err)
		}
	}

	return nil
}

func (i *Ips) Symbolicate210WithDatabase(dbURL string) (err error) {

	db := server.NewServer(dbURL)

	if err := db.Ping(); err != nil {
		return fmt.Errorf("failed symbolicate panic 210: %w", err)
	}

	if ok, err := db.HasIPSW(i.Header.Version(), i.Header.Build(), i.Payload.Product); err != nil {
		return fmt.Errorf("failed symbolicate panic 210: %w", err)
	} else {
		if !ok {
			need := fmt.Sprintf("%s (%s) for %s", i.Header.Version(), i.Header.Build(), i.Payload.Product)
			return fmt.Errorf("failed symbolicate panic 210: required IPSW not found in symbol server database; need %s", need)
		}
	}

	i.Payload.panic210, err = parsePanicString210(i.Payload.PanicString)
	if err != nil {
		return fmt.Errorf("failed to parse panic string: %w", err)
	}

	total := len(i.Payload.BinaryImages)

	// add default binary image names
	for idx, img := range i.Payload.BinaryImages {
		switch img.Source {
		case "Absolute":
			i.Payload.BinaryImages[idx].Name = "absolute"
			total--
		case "Kernel":
			i.Payload.BinaryImages[idx].Name = "kernel"
			if i.Payload.panic210 != nil && i.Payload.panic210.KernelSlide != nil {
				i.Payload.BinaryImages[idx].Slide = i.Payload.panic210.KernelSlide.Value.(uint64)
			}
			total--
		case "KernelCache":
			i.Payload.BinaryImages[idx].Name = "kernelcache"
			if i.Payload.panic210 != nil {
				// if i.Payload.panic210.KernelTextBase != nil {
				// 	i.Payload.BinaryImages[idx].Base = i.Payload.panic210.KernelTextBase.Value.(uint64)
				// }
				if i.Payload.panic210.KernelCacheSlide != nil {
					i.Payload.BinaryImages[idx].Slide = i.Payload.panic210.KernelCacheSlide.Value.(uint64)
				} else if i.Payload.panic210.KernelSlide != nil {
					i.Payload.BinaryImages[idx].Slide = i.Payload.panic210.KernelSlide.Value.(uint64)
				}
				if i.Payload.panic210.KernelUUID != nil {
					i.Payload.BinaryImages[idx].UUID = i.Payload.panic210.KernelUUID.Value.(string)
				}
			}
			total--
		case "KernelTextExec":
			i.Payload.BinaryImages[idx].Name = "kernelcache (__TEXT_EXEC)"
			if i.Payload.panic210 != nil && i.Payload.panic210.KernelTextExecSlide != nil {
				i.Payload.BinaryImages[idx].Slide = i.Payload.panic210.KernelTextExecSlide.Value.(uint64)
			}
			total--
		case "SharedCache":
			i.Payload.BinaryImages[idx].Name = "dyld_shared_cache"
			total--
		case "SharedCacheLibrary":
			i.Payload.BinaryImages[idx].Name = "dyld_shared_cache (library)"
			total--
		}
	}

	for idx, img := range i.Payload.BinaryImages {
		if m, err := db.GetMachO(strings.ToUpper(img.UUID)); err == nil {
			if i.Payload.BinaryImages[idx].Name != "kernelcache" {
				i.Payload.BinaryImages[idx].Path = m.GetPath()
				i.Payload.BinaryImages[idx].Name = m.GetPath()
				i.Payload.BinaryImages[idx].Slide = i.Payload.BinaryImages[idx].Base - m.TextStart
			}
			total--
		} else {
			log.WithFields(log.Fields{
				"uuid": img.UUID,
				"name": img.Name,
			}).Debug("failed to find macho for uuid")
		}
	}

	if total > 0 {
		log.WithFields(log.Fields{
			"total": total,
		}).Debug("missing binary images")
	}

	for pid, proc := range i.Payload.ProcessByPid {
		for tid, thread := range proc.ThreadByID {
			for idx, frame := range thread.UserFrames {
				i.Payload.ProcessByPid[pid].ThreadByID[tid].UserFrames[idx].ImageOffset += i.Payload.BinaryImages[frame.ImageIndex].Base
				if i.Payload.BinaryImages[frame.ImageIndex].Slide != 0 {
					i.Payload.ProcessByPid[pid].ThreadByID[tid].UserFrames[idx].Slide = i.Payload.BinaryImages[frame.ImageIndex].Slide
				}
				if len(i.Payload.BinaryImages[frame.ImageIndex].Name) > 0 {
					i.Payload.ProcessByPid[pid].ThreadByID[tid].UserFrames[idx].ImageName = i.Payload.BinaryImages[frame.ImageIndex].Name
				} else {
					if strings.HasPrefix(i.Payload.ProcessByPid[pid].ThreadByID[tid].UserFrames[idx].ImageName, "image_") {
						i.Payload.ProcessByPid[pid].ThreadByID[tid].UserFrames[idx].ImageName += fmt.Sprintf(" (probably %s)", proc.Name)
					}
				}
				if i.Payload.ProcessByPid[pid].ThreadByID[tid].UserFrames[idx].ImageName == "absolute" {
					continue // skip absolute
				} else if i.Payload.ProcessByPid[pid].ThreadByID[tid].UserFrames[idx].ImageName == "dyld_shared_cache" {
					dsc, err := db.GetDSC(strings.ToUpper(i.Payload.BinaryImages[frame.ImageIndex].UUID))
					if err != nil {
						return fmt.Errorf("failed to get DSC for uuid: %w", err)
					}
					if dsc.SharedRegionStart != i.Payload.BinaryImages[frame.ImageIndex].Base {
						i.Payload.ProcessByPid[pid].ThreadByID[tid].UserFrames[idx].Slide = i.Payload.BinaryImages[frame.ImageIndex].Base - dsc.SharedRegionStart
					}
					// lookup symbol in DSC dylib
					if img, err := db.GetDSCImage(dsc.UUID, i.Payload.ProcessByPid[pid].ThreadByID[tid].UserFrames[idx].ImageOffset); err == nil {
						i.Payload.ProcessByPid[pid].ThreadByID[tid].UserFrames[idx].ImageName = filepath.Base(img.GetPath())
						if sym, err := db.GetSymbol(img.UUID, i.Payload.ProcessByPid[pid].ThreadByID[tid].UserFrames[idx].ImageOffset); err == nil {
							i.Payload.ProcessByPid[pid].ThreadByID[tid].UserFrames[idx].Symbol = demangleSym(i.Config.Demangle, sym.GetName())
							if i.Payload.ProcessByPid[pid].ThreadByID[tid].UserFrames[idx].ImageOffset-sym.Start != 0 {
								i.Payload.ProcessByPid[pid].ThreadByID[tid].UserFrames[idx].SymbolLocation = i.Payload.ProcessByPid[pid].ThreadByID[tid].UserFrames[idx].ImageOffset - sym.Start
							}
						} else {
							i.Payload.ProcessByPid[pid].ThreadByID[tid].UserFrames[idx].Symbol = fmt.Sprintf("func_%x", i.Payload.ProcessByPid[pid].ThreadByID[tid].UserFrames[idx].ImageOffset)
						}
					} else {
						log.WithFields(log.Fields{
							"proc":   fmt.Sprintf("%s [%d]", proc.Name, pid),
							"thread": tid,
							"frame":  idx,
							"img":    i.Payload.ProcessByPid[pid].ThreadByID[tid].UserFrames[idx].ImageName,
						}).Debugf("failed to find DSC image containing offset %#x", i.Payload.ProcessByPid[pid].ThreadByID[tid].UserFrames[idx].ImageOffset)
					}
				} else { // "Process"
					if sym, err := db.GetSymbol(
						strings.ToUpper(i.Payload.BinaryImages[frame.ImageIndex].UUID),
						i.Payload.ProcessByPid[pid].ThreadByID[tid].UserFrames[idx].ImageOffset-
							i.Payload.ProcessByPid[pid].ThreadByID[tid].UserFrames[idx].Slide,
					); err == nil {
						i.Payload.ProcessByPid[pid].ThreadByID[tid].UserFrames[idx].Symbol = demangleSym(i.Config.Demangle, sym.GetName())
						if i.Payload.ProcessByPid[pid].ThreadByID[tid].UserFrames[idx].ImageOffset-sym.Start != 0 {
							i.Payload.ProcessByPid[pid].ThreadByID[tid].UserFrames[idx].SymbolLocation =
								i.Payload.ProcessByPid[pid].ThreadByID[tid].UserFrames[idx].ImageOffset -
									i.Payload.ProcessByPid[pid].ThreadByID[tid].UserFrames[idx].Slide -
									sym.Start
						}
					} else {
						// sometimes a frame will report using `dyld` but the offset is not in any function or in the binary image (e.g. in memory macho)
						if i.Payload.ProcessByPid[pid].ThreadByID[tid].UserFrames[idx].ImageName == "/usr/lib/dyld" {
							i.Payload.ProcessByPid[pid].ThreadByID[tid].UserFrames[idx].ImageName += " (??? in memory macho)"
						}
						log.WithFields(log.Fields{
							"proc":   fmt.Sprintf("%s [%d]", proc.Name, pid),
							"thread": tid,
							"frame":  idx,
							"img":    i.Payload.ProcessByPid[pid].ThreadByID[tid].UserFrames[idx].ImageName,
						}).Debugf("failed to find symbol for process offset %#x",
							i.Payload.ProcessByPid[pid].ThreadByID[tid].UserFrames[idx].ImageOffset-
								i.Payload.ProcessByPid[pid].ThreadByID[tid].UserFrames[idx].Slide)
					}
				}
			}
			for idx, frame := range thread.KernelFrames {
				i.Payload.ProcessByPid[pid].ThreadByID[tid].KernelFrames[idx].ImageOffset += i.Payload.BinaryImages[frame.ImageIndex].Base
				if i.Payload.BinaryImages[frame.ImageIndex].Slide != 0 {
					i.Payload.ProcessByPid[pid].ThreadByID[tid].KernelFrames[idx].Slide = i.Payload.BinaryImages[frame.ImageIndex].Slide
				}
				if len(i.Payload.BinaryImages[frame.ImageIndex].Name) > 0 {
					i.Payload.ProcessByPid[pid].ThreadByID[tid].KernelFrames[idx].ImageName = i.Payload.BinaryImages[frame.ImageIndex].Name
				} else {
					if strings.HasPrefix(i.Payload.ProcessByPid[pid].ThreadByID[tid].KernelFrames[idx].ImageName, "image_") {
						i.Payload.ProcessByPid[pid].ThreadByID[tid].KernelFrames[idx].ImageName += " (maybe a kext)"
					}
				}
				if i.Payload.ProcessByPid[pid].ThreadByID[tid].KernelFrames[idx].ImageName == "absolute" {
					continue // skip absolute
				} else if i.Payload.ProcessByPid[pid].ThreadByID[tid].KernelFrames[idx].ImageName == "kernelcache" {
					if sym, err := db.GetSymbol(
						strings.ToUpper(i.Payload.BinaryImages[frame.ImageIndex].UUID),
						i.Payload.ProcessByPid[pid].ThreadByID[tid].KernelFrames[idx].ImageOffset & ^uint64(1<<63),
					); err == nil {
						sym.Start |= uint64(1 << 63)
						sym.End |= uint64(1 << 63)
						i.Payload.ProcessByPid[pid].ThreadByID[tid].KernelFrames[idx].Symbol = demangleSym(i.Config.Demangle, sym.GetName())
						if i.Payload.ProcessByPid[pid].ThreadByID[tid].KernelFrames[idx].ImageOffset-sym.Start != 0 {
							i.Payload.ProcessByPid[pid].ThreadByID[tid].KernelFrames[idx].SymbolLocation =
								i.Payload.ProcessByPid[pid].ThreadByID[tid].KernelFrames[idx].ImageOffset - sym.Start
						}
					} else {
						log.WithFields(log.Fields{
							"proc":   fmt.Sprintf("%s [%d]", proc.Name, pid),
							"thread": tid,
							"frame":  idx,
							"img":    i.Payload.ProcessByPid[pid].ThreadByID[tid].KernelFrames[idx].ImageName,
						}).Debugf("failed to find symbol for kernel frame image offset %#x", i.Payload.ProcessByPid[pid].ThreadByID[tid].KernelFrames[idx].ImageOffset)
					}
				} else {
					log.WithFields(log.Fields{
						"proc":   fmt.Sprintf("%s [%d]", proc.Name, pid),
						"thread": tid,
						"frame":  idx,
						"img":    i.Payload.ProcessByPid[pid].ThreadByID[tid].KernelFrames[idx].ImageName,
						"offset": fmt.Sprintf("%#x", i.Payload.ProcessByPid[pid].ThreadByID[tid].KernelFrames[idx].ImageOffset),
					}).Errorf("unexpected image")
				}
			}
		}
	}

	// Generate IDA scripts if requested
	if i.Config.IDAScript {
		if err := i.generateIDAScripts(); err != nil {
			return fmt.Errorf("failed to generate IDA scripts: %w", err)
		}
	}

	return nil
}

func fmtState(states []string) string {
	var out []string
	for _, s := range states {
		switch s {
		case "TH_WAIT", "TH_UNINT":
			out = append(out, colorAddr(s))
		case "TH_RUN", "TH_IDLE":
			out = append(out, colorBold(s))
		default:
			out = append(out, s)
		}
	}
	return strings.Join(out, ", ")
}

func colorVMSummary(in string) string {
	separatorMatch := regexp.MustCompile(`=+`)
	in = separatorMatch.ReplaceAllStringFunc(in, func(s string) string {
		return colorField(s)
	})
	return in
}

func (i *Ips) String() string {
	var out string

	switch i.Header.BugType {
	case "Panic", "210", "288":
		out = fmt.Sprintf("[%s] - %s - %s %s\n\n", colorTime(i.Header.Timestamp.Format("02Jan2006 15:04:05")), colorError(i.Header.BugTypeDesc), i.Payload.Product, i.Payload.Build)
		if i.Payload.panic210 == nil {
			var err error
			i.Payload.panic210, err = parsePanicString210(i.Payload.PanicString)
			if err != nil {
				log.Errorf("failed to parse panic string: %w", err)
			}
		}
		if i.Config.Verbose {
			if len(i.Payload.PanicString) > 0 {
				out += fmt.Sprintf("%s: %s\n", colorField("Panic String"), i.Payload.PanicString)
			}
		} else {
			out += i.Payload.panic210.String()
		}
		if len(i.Payload.PanicFlags) > 0 {
			out += fmt.Sprintf("%s: %s\n", colorField("Panic Flags"), i.Payload.PanicFlags)
		}
		out += "\n" + i.Payload.MemoryStatus.String()
		out += i.Payload.OtherString + "\n"
		var pids []int
		for pid := range i.Payload.ProcessByPid {
			pids = append(pids, pid)
		}
		sort.Ints(pids)
		for _, pid := range pids {
			p := i.Payload.ProcessByPid[pid]
			paniced := ""
			if p.ID == i.Payload.panic210.PanickedTask.PID {
				paniced = colorError(" (Panicked)")
			} else {
				/* filter procs */
				if !i.Config.All {
					if i.Config.Running {
						notRunning := true
						// check if any thread is running
						for _, t := range p.ThreadByID {
							if slices.Contains(t.State, "TH_RUN") {
								notRunning = false
								break
							}
						}
						if notRunning {
							continue
						}
					} else if len(i.Config.Process) > 0 {
						if p.Name != i.Config.Process {
							continue
						}
					} else {
						continue
					}
				}
			}
			out += fmt.Sprintf(colorField("Process")+": %s [%s]%s\n", colorImage(p.Name), colorBold("%d", p.ID), paniced)
			for _, t := range p.ThreadByID {
				paniced = ""
				if t.ID == i.Payload.panic210.PanickedThread.TID {
					paniced = colorError("       (Panicked)")
				} else {
					/* filter threads */
					if !i.Config.All {
						if i.Config.Running {
							if !slices.Contains(t.State, "TH_RUN") {
								continue
							}
						} else if len(i.Config.Process) > 0 {
							if p.Name != i.Config.Process {
								continue
							}
						} else {
							continue
						}
					}
				}
				out += fmt.Sprintf(colorField("  Thread")+": %s%s\n", colorBold("%d", t.ID), paniced)
				if len(t.Name) > 0 {
					out += fmt.Sprintf("    Name:           %s\n", colorTime(t.Name))
				}
				if len(t.DispatchQueueLabel) > 0 {
					out += fmt.Sprintf("    Queue:          %s\n", t.DispatchQueueLabel)
				}
				out += fmt.Sprintf("    State:          %s\n", fmtState(t.State))
				out += fmt.Sprintf("    Base Priority:  %d\n", t.BasePriority)
				out += fmt.Sprintf("    Sched Priority: %d\n", t.SchedPriority)
				out += fmt.Sprintf("    User Time:      %d usec\n", t.UserUsec)
				out += fmt.Sprintf("    System Time:    %d usec\n", t.SystemUsec)
				if len(t.UserFrames) > 0 {
					out += "    User Frames:\n"
					isPanickedThread := i.Payload.panic210 != nil &&
						p.ID == i.Payload.panic210.PanickedTask.PID &&
						t.ID == i.Payload.panic210.PanickedThread.TID
					buf := bytes.NewBufferString("")
					w := tabwriter.NewWriter(buf, 0, 0, 1, ' ', 0)
					for idx, f := range t.UserFrames {
						if f.ImageName == "absolute" {
							continue
						}
						addr, slideVal, _ := i.panicFrameAddr(f)
						slideInfo := ""
						if slideVal > 0 {
							slideInfo = fmt.Sprintf(" (slide=%#x)", slideVal)
						}
						symloc := ""
						if f.SymbolLocation > 0 {
							symloc = fmt.Sprintf(" + %d", f.SymbolLocation)
							if i.Config.Hex {
								symloc = fmt.Sprintf(" + %#x", f.SymbolLocation)
							}
						}
						fmt.Fprintf(w, "      %02d: %s\t%s%s %s%s\n", idx, colorImage(f.ImageName), colorAddr("%#x", addr), slideInfo, colorField(f.Symbol), symloc)
						// Add peek disassembly for panicked thread frames
						if i.Config.Peek && isPanickedThread && len(f.PeekBytes) > 0 {
							w.Flush()
							out += buf.String()
							buf.Reset()
							isDSC := i.isDSCFrame(f)
							out += formatPeekDisassembly(f.PeekBytes, f.PeekAddr, f.PeekFrameIdx, slideVal, i.Config.KernelSlide, i.Config.DSCSlide, isDSC, i.Config.Unslid, f.PeekSymbols, i.Config.Demangle)
						}
					}
					w.Flush()
					out += buf.String()
				}
				if len(t.KernelFrames) > 0 {
					out += "    Kernel Frames:\n"
					isPanickedThread := i.Payload.panic210 != nil &&
						p.ID == i.Payload.panic210.PanickedTask.PID &&
						t.ID == i.Payload.panic210.PanickedThread.TID
					buf := bytes.NewBufferString("")
					w := tabwriter.NewWriter(buf, 0, 0, 1, ' ', 0)
					for idx, f := range t.KernelFrames {
						if f.ImageName == "absolute" {
							continue
						}
						addr, slideVal, _ := i.panicFrameAddr(f)
						slideInfo := ""
						if slideVal > 0 {
							slideInfo = fmt.Sprintf(" (slide=%#x)", slideVal)
						}
						symloc := ""
						if f.SymbolLocation > 0 {
							symloc = fmt.Sprintf(" + %d", f.SymbolLocation)
							if i.Config.Hex {
								symloc = fmt.Sprintf(" + %#x", f.SymbolLocation)
							}
						}
						fmt.Fprintf(w, "      %02d: %s\t%s%s %s%s\n", idx, colorImage(f.ImageName), colorAddr("%#x", addr), slideInfo, colorField(f.Symbol), symloc)
						// Add peek disassembly for panicked thread frames
						if i.Config.Peek && isPanickedThread && len(f.PeekBytes) > 0 {
							w.Flush()
							out += buf.String()
							buf.Reset()
							// Kernel frames are never DSC frames, so pass false for isDSCFrame
							out += formatPeekDisassembly(f.PeekBytes, f.PeekAddr, f.PeekFrameIdx, slideVal, i.Config.KernelSlide, i.Config.DSCSlide, false, i.Config.Unslid, f.PeekSymbols, i.Config.Demangle)
						}
					}
					w.Flush()
					out += buf.String()
				}
			}
			out += "\n"
		}
		if len(i.Payload.Notes) > 0 {
			out += colorField("NOTES") + ":\n"
			for _, n := range i.Payload.Notes {
				out += fmt.Sprintf("    - %s\n", n)
			}
		}
	case "Crash", "309":
		out = fmt.Sprintf("[%s] - %s\n\n", colorTime(i.Header.Timestamp.Format("02Jan2006 15:04:05")), colorError(i.Header.BugTypeDesc))
		out += fmt.Sprintf(
			colorField("Process")+":        %s [%d]\n"+
				colorField("Path")+":           %s\n"+
				colorField("Parent")+":         %s [%d]\n"+
				colorField("Hardware Model")+": %s\n"+
				colorField("OS Version")+":     %s\n"+
				colorField("BuildID")+":        %s\n"+
				colorField("LockdownMode")+":            %d\n"+
				colorField("Was Unlocked Since Boot")+": %d\n"+
				colorField("Is Locked")+":               %d\n",
			i.Payload.ProcName, i.Payload.PID,
			i.Payload.ProcPath,
			i.Payload.ParentProc, i.Payload.ParentPid,
			i.Payload.ModelCode,
			i.Payload.OsVersion.Train,
			i.Payload.OsVersion.Build,
			i.Payload.LockdownMode,
			i.Payload.WasUnlockedSinceBoot,
			i.Payload.IsLocked,
		)
		if i.Payload.SharedCache.Size > 0 {
			out += fmt.Sprintf(colorField("Shared Cache")+":        %s %s: %#x %s: %d\n", i.Payload.SharedCache.UUID, colorField("base"), i.Payload.SharedCache.Base, colorField("size"), i.Payload.SharedCache.Size)
		}
		var exception Exception
		if err := mapstructure.Decode(i.Payload.Exception, &exception); err == nil {
			out += fmt.Sprintf("\n%s:      %s (%s) %s\n", colorField("Exception Type"), colorBold(exception.Type), exception.Signal, exception.Message)
			if len(exception.Subtype) > 0 {
				out += fmt.Sprintf(colorField("Exception Subtype")+":   %s\n", exception.Subtype)
			}
		} else {
			out += fmt.Sprintf(colorField("Exception")+": %s\n", i.Payload.Exception)
		}
		if len(i.Payload.VmRegionInfo) > 0 {
			out += fmt.Sprintf(colorField("VM Region Info")+": %s\n", i.Payload.VmRegionInfo)
		}
		if i.Payload.Asi != nil {
			out += colorField("ASI") + ":\n"
			for k, v := range i.Payload.Asi {
				out += fmt.Sprintf("    %s:\n", k)
				for _, s := range v {
					out += fmt.Sprintf("      - %s\n", s)
				}
			}
			out += "\n"
		}
		for _, t := range i.Payload.Threads {
			out += fmt.Sprintf(colorField("Thread")+" %s:", colorBold("%d", t.ID))
			if len(t.Name) > 0 {
				out += colorField(" name") + ": " + t.Name
				if len(t.Queue) > 0 {
					out += ","
				}
			}
			if len(t.Queue) > 0 {
				out += colorField(" queue") + ": " + t.Queue
			}
			if t.Triggered {
				out += colorError(" (Crashed)\n")
			} else {
				out += "\n"
			}
			if len(t.Frames) > 0 {
				buf := bytes.NewBufferString("")
				w := tabwriter.NewWriter(buf, 0, 0, 1, ' ', 0)
				for idx, f := range t.Frames {
					addr := i.Payload.UsedImages[f.ImageIndex].Base + f.ImageOffset
					slideInfo := ""
					if i.Config.Unslid && f.Slide != 0 && addr >= f.Slide {
						addr -= f.Slide
						slideInfo = fmt.Sprintf(" (unslid %#x)", f.Slide)
					}
					symloc := ""
					if f.SymbolLocation > 0 {
						symloc = fmt.Sprintf(" + %d", f.SymbolLocation)
						if i.Config.Hex {
							symloc = fmt.Sprintf(" + %#x", f.SymbolLocation)
						}
					}
					fmt.Fprintf(w, "  %02d: %s\t%s%s %s%s\n", idx, colorImage(i.Payload.UsedImages[f.ImageIndex].Name), colorAddr("%#x", addr), slideInfo, colorField(f.Symbol), symloc)
				}
				w.Flush()
				out += buf.String()
			}
			if t.Triggered || i.Config.All {
				out += colorField("Thread") + colorBold(" %d ", t.ID) + colorField(t.ThreadState.Flavor) + "\n" + t.ThreadState.String()
				if t.Triggered {
					if len(i.Payload.InstructionByteStream.BeforePC) > 0 {
						out += colorField("Instructions") + "\n"
						if b64data, err := base64.StdEncoding.WithPadding(base64.StdPadding).DecodeString(i.Payload.InstructionByteStream.BeforePC); err != nil {
							log.WithError(err).Errorf("failed to decode BeforePC instruction byte stream")
						} else {
							if instructions, err := disassemble.GetInstructions(t.ThreadState.PC.Value-(10*4), b64data); err != nil {
								log.WithError(err).Errorf("failed to disassemble BeforePC instructions")
							} else {
								pad := "    "
								for _, block := range instructions.Blocks() {
									for _, i := range block {
										opStr := strings.TrimSpace(strings.TrimPrefix(i.String(), i.Operation.String()))
										out += fmt.Sprintf("%s%s:  %s   %s %s\n",
											pad,
											colorAddr("%#08x", i.Address),
											disassemble.GetOpCodeByteString(i.Raw),
											colorImage("%-7s", i.Operation),
											disass.ColorOperands(opStr),
										)
									}
									out += "\n"
								}
							}
						}
					}
					if len(i.Payload.InstructionByteStream.AtPC) > 0 {
						out = strings.TrimSuffix(out, "\n")
						if b64data, err := base64.StdEncoding.WithPadding(base64.StdPadding).DecodeString(i.Payload.InstructionByteStream.AtPC); err != nil {
							log.WithError(err).Errorf("failed to decode AtPC instruction byte stream")
						} else {
							if instructions, err := disassemble.GetInstructions(t.ThreadState.PC.Value, b64data); err != nil {
								log.WithError(err).Errorf("failed to disassemble AtPC instructions")
							} else {
								for idx, block := range instructions.Blocks() {
									for jdx, i := range block {
										pad := "    "
										if idx == 0 && jdx == 0 {
											pad = colorError("PC=>")
										}
										opStr := strings.TrimSpace(strings.TrimPrefix(i.String(), i.Operation.String()))
										out += fmt.Sprintf("%s%s:  %s   %s %s\n",
											pad,
											colorAddr("%#08x", i.Address),
											disassemble.GetOpCodeByteString(i.Raw),
											colorImage("%-7s", i.Operation),
											disass.ColorOperands(opStr),
										)
									}
									out += "\n"
								}
							}
						}
					}
				}
			}
			out += "\n"
		}
		if len(i.Payload.LastExceptionBacktrace) > 0 {
			out += colorField("Last Exception Backtrace") + ":\n"
			buf := bytes.NewBufferString("")
			w := tabwriter.NewWriter(buf, 0, 0, 1, ' ', 0)
			for idx, f := range i.Payload.LastExceptionBacktrace {
				addr := i.Payload.UsedImages[f.ImageIndex].Base + f.ImageOffset
				slideInfo := ""
				if i.Config.Unslid && f.Slide != 0 && addr >= f.Slide {
					addr -= f.Slide
					slideInfo = fmt.Sprintf(" (unslid %#x)", f.Slide)
				}
				symloc := ""
				if f.SymbolLocation > 0 {
					symloc = fmt.Sprintf(" + %d", f.SymbolLocation)
					if i.Config.Hex {
						symloc = fmt.Sprintf(" + %#x", f.SymbolLocation)
					}
				}
				fmt.Fprintf(w, "  %02d: %s\t%s%s %s%s\n", idx, colorImage(i.Payload.UsedImages[f.ImageIndex].Name), colorAddr("%#x", addr), slideInfo, colorField(f.Symbol), symloc)
			}
			w.Flush()
			out += buf.String() + "\n"
		}
		if len(i.Payload.VMSummary) > 0 {
			out += colorField("VM Summary") + ":\n" + colorVMSummary(i.Payload.VMSummary)
		}
	default:
		return fmt.Sprintf("%s: (unsupported, notify author)", i.Header.BugType)
	}

	return out
}
