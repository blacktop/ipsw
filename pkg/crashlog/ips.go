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

	"github.com/apex/log"
	"github.com/blacktop/arm64-cgo/disassemble"
	"github.com/blacktop/go-macho"
	"github.com/blacktop/go-macho/types"
	"github.com/blacktop/ipsw/internal/commands/dsc"
	"github.com/blacktop/ipsw/internal/demangle"
	"github.com/blacktop/ipsw/internal/search"
	"github.com/blacktop/ipsw/internal/swift"
	"github.com/blacktop/ipsw/pkg/disass"
	"github.com/fatih/color"
)

// REFERENCES:
//     - https://developer.apple.com/documentation/xcode/interpreting-the-json-format-of-a-crash-report
//     - https://github.com/zed-industries/zed/blob/main/crates/collab/src/api/ips_file.rs

//go:embed data/log_type.gz
var logTypeData []byte

var colorTime = color.New(color.Bold, color.FgHiGreen).SprintFunc()
var colorError = color.New(color.Bold, color.FgHiRed).SprintFunc()
var colorAddr = color.New(color.Faint).SprintfFunc()
var colorBold = color.New(color.Bold).SprintfFunc()
var colorImage = color.New(color.Bold, color.FgHiMagenta).SprintfFunc()
var colorField = color.New(color.Bold, color.FgHiBlue).SprintFunc()

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
	All      bool
	Running  bool
	Unslid   bool
	Demangle bool
}

type Ips struct {
	Header  IpsMetadata
	Payload IPSPayload
	Config  *Config
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
	Timestamp        Timestamp `json:"timestamp,omitempty"`
	SliceUUID        string    `json:"slice_uuid,omitempty"`
	ShareWithAppDevs int       `json:"share_with_app_devs,omitempty"`
	IsFirstParty     int       `json:"is_first_party,omitempty"`
	RootsInstalled   int       `json:"roots_installed,omitempty"`
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
	} `json:"memoryPages,omitempty"`
	MemoryPressure        bool `json:"memoryPressure,omitempty"`
	MemoryPressureDetails struct {
		PagesReclaimed int64 `json:"pagesReclaimed,omitempty"`
		PagesWanted    int64 `json:"pagesWanted,omitempty"`
	} `json:"memoryPressureDetails,omitempty"`
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
	LR     Register   `json:"lr,omitempty"`
	CPSR   Register   `json:"cpsr,omitempty"`
	FP     Register   `json:"fp,omitempty"`
	SP     Register   `json:"sp,omitempty"`
	ESR    Register   `json:"esr,omitempty"`
	PC     Register   `json:"pc,omitempty"`
	FAR    Register   `json:"far,omitempty"`
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
	ThreadState ThreadState `json:"threadState,omitempty"`
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
	MemoryStatus     MemoryStatus    `json:"memoryStatus,omitempty"`
	ProcessByPid     map[int]Process `json:"processByPid,omitempty"`
	BinaryImages     []BinaryImage   `json:"binaryImages,omitempty"`
	Notes            []string        `json:"notes,omitempty"`
	/* Userspace Fields */
	Asi map[string][]string `json:"asi,omitempty"` // Additional application-specific logging. The properties of this object include an array of log strings.
	// For more information, see Diagnostic messages. This appears in a translated report under Application Specific Information.
	// https://developer.apple.com/documentation/xcode/examining-the-fields-in-a-crash-report#Diagnostic-messages
	IsCorpse              bool       `json:"isCorpse,omitempty"`
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
	OsVersion             OsVersion  `json:"osVersion,omitempty"`
	CaptureTime           string     `json:"captureTime,omitempty"`
	PID                   int        `json:"pid,omitempty"`
	CPUType               string     `json:"cpuType,omitempty"`
	RootsInstalled        int        `json:"roots_installed,omitempty"`
	BugType               string     `json:"bug_type,omitempty"`
	BundleInfo            BundleInfo `json:"bundleInfo,omitempty"`
	StoreInfo             StoreInfo  `json:"storeInfo,omitempty"`
	ParentProc            string     `json:"parentProc,omitempty"`
	ParentPid             int        `json:"parentPid,omitempty"`
	CoalitionName         string     `json:"coalitionName,omitempty"`
	LockdownMode          int        `json:"ldm,omitempty"`
	WasUnlockedSinceBoot  int        `json:"wasUnlockedSinceBoot,omitempty"`
	IsLocked              int        `json:"isLocked,omitempty"`
	InstructionByteStream struct {
		BeforePC string `json:"beforePC,omitempty"`
		AtPC     string `json:"atPC,omitempty"`
	} `json:"instructionByteStream,omitempty"`
	CodeSigningID                 string       `json:"codeSigningID,omitempty"`
	CodeSigningTeamID             string       `json:"codeSigningTeamID,omitempty"`
	CodeSigningFlags              int          `json:"codeSigningFlags,omitempty"`
	CodeSigningValidationCategory int          `json:"codeSigningValidationCategory,omitempty"`
	CodeSigningTrustLevel         int          `json:"codeSigningTrustLevel,omitempty"`
	CodeSigningMonitor            int          `json:"codeSigningMonitor,omitempty"`
	ThrottleTimeout               int64        `json:"throttleTimeout,omitempty"`
	BasebandVersion               string       `json:"basebandVersion,omitempty"`
	Exception                     Exception    `json:"exception,omitempty"`
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
	} `json:"sharedCache,omitempty"`
	LegacyInfo struct {
		ThreadTriggered struct {
			Queue string `json:"queue,omitempty"`
		} `json:"threadTriggered,omitempty"`
	} `json:"legacyInfo,omitempty"`
	TrialInfo struct {
		Rollouts []struct {
			RolloutID     string `json:"rolloutId,omitempty"`
			FactorPackIds struct {
			} `json:"factorPackIds,omitempty"`
			DeploymentID int `json:"deploymentId,omitempty"`
		} `json:"rollouts,omitempty"`
		Experiments []struct {
			TreatmentID  string `json:"treatmentId,omitempty"`
			ExperimentID string `json:"experimentId,omitempty"`
			DeploymentID int    `json:"deploymentId,omitempty"`
		} `json:"experiments,omitempty"`
	} `json:"trialInfo,omitempty"`
	DTAppStoreToolsBuild string      `json:"DTAppStoreToolsBuild,omitempty"`
	Version              int         `json:"version,omitempty"`
	VMSummary            string      `json:"vmSummary,omitempty"`
	VmRegionInfo         string      `json:"vmregioninfo,omitempty"`
	Termination          Termination `json:"termination,omitempty"`
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

func (i *Ips) Symbolicate210(ipswPath string) error {
	total := len(i.Payload.BinaryImages)

	// add default binary image names
	for idx, img := range i.Payload.BinaryImages {
		switch img.Source {
		case "Absolute":
			i.Payload.BinaryImages[idx].Name = "absolute"
			total--
		case "Kernel":
			i.Payload.BinaryImages[idx].Name = "kernel"
			total--
		case "KernelCache":
			i.Payload.BinaryImages[idx].Name = "kernelcache"
			total--
		case "KernelTextExec":
			i.Payload.BinaryImages[idx].Name = "kernelcache (__TEXT_EXEC)"
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
	if err := search.ForEachMachoInIPSW(ipswPath, func(path string, m *macho.File) error {
		if total == 0 {
			return ErrDone // break
		}
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
					} else {
						fn.StartAddr += i.Payload.BinaryImages[idx].Slide
						fn.EndAddr += i.Payload.BinaryImages[idx].Slide
						fn.Name = fmt.Sprintf("func_%x", fn.StartAddr)
						machoFuncMap[i.Payload.BinaryImages[idx].Name] = append(machoFuncMap[i.Payload.BinaryImages[idx].Name], fn)
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

	// // print any binary images that are missing names
	// for idx, img := range i.Payload.BinaryImages {
	// 	if len(img.Name) == 0 {
	// 		fmt.Printf("idx: %d - %v\n", idx, img)
	// 	}
	// }

	ctx, f, err := dsc.OpenFromIPSW(ipswPath)
	if err != nil {
		return fmt.Errorf("failed to open DSC from IPSW: %w", err)
	}
	defer ctx.Unmount()

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
					if f.Headers[f.UUID].SharedRegionStart != i.Payload.BinaryImages[frame.ImageIndex].Base {
						i.Payload.ProcessByPid[pid].ThreadByID[tid].UserFrames[idx].Slide = i.Payload.BinaryImages[frame.ImageIndex].Base - f.Headers[f.UUID].SharedRegionStart
					}
					// lookup symbol in DSC dylib
					if img, err := f.GetImageContainingVMAddr(i.Payload.ProcessByPid[pid].ThreadByID[tid].UserFrames[idx].ImageOffset); err == nil {
						i.Payload.ProcessByPid[pid].ThreadByID[tid].UserFrames[idx].ImageName = filepath.Base(img.Name)
						img.ParseLocalSymbols(false)
						img.ParsePublicSymbols(false)
						m, err := img.GetMacho()
						if err != nil {
							return fmt.Errorf("failed to get macho from image: %w", err)
						}
						if fn, err := m.GetFunctionForVMAddr(i.Payload.ProcessByPid[pid].ThreadByID[tid].UserFrames[idx].ImageOffset); err == nil {
							if sym, ok := f.AddressToSymbol[fn.StartAddr]; ok {
								if i.Config.Demangle {
									if strings.HasPrefix(sym, "_$s") || strings.HasPrefix(sym, "$s") { // TODO: better detect swift symbols
										i.Payload.ProcessByPid[pid].ThreadByID[tid].UserFrames[idx].Symbol, _ = swift.Demangle(sym)
									} else if strings.HasPrefix(sym, "__Z") || strings.HasPrefix(sym, "_Z") {
										i.Payload.ProcessByPid[pid].ThreadByID[tid].UserFrames[idx].Symbol = demangle.Do(sym, false, false)
									} else {
										i.Payload.ProcessByPid[pid].ThreadByID[tid].UserFrames[idx].Symbol = sym
									}
								} else {
									i.Payload.ProcessByPid[pid].ThreadByID[tid].UserFrames[idx].Symbol = sym
								}
								if i.Payload.ProcessByPid[pid].ThreadByID[tid].UserFrames[idx].ImageOffset-fn.StartAddr != 0 {
									i.Payload.ProcessByPid[pid].ThreadByID[tid].UserFrames[idx].SymbolLocation = i.Payload.ProcessByPid[pid].ThreadByID[tid].UserFrames[idx].ImageOffset - fn.StartAddr
								}
							} else {
								i.Payload.ProcessByPid[pid].ThreadByID[tid].UserFrames[idx].Symbol = fmt.Sprintf("func_%x", fn.StartAddr)
							}
						}
					}
				} else { // "Process"
					// lookup symbol in MachO symbol map
					if funcs, ok := machoFuncMap[i.Payload.ProcessByPid[pid].ThreadByID[tid].UserFrames[idx].ImageName]; ok {
						found := false
						for _, fn := range funcs {
							if fn.StartAddr <= i.Payload.ProcessByPid[pid].ThreadByID[tid].UserFrames[idx].ImageOffset && i.Payload.ProcessByPid[pid].ThreadByID[tid].UserFrames[idx].ImageOffset < fn.EndAddr {
								found = true
								if i.Config.Demangle {
									if strings.HasPrefix(fn.Name, "_$s") || strings.HasPrefix(fn.Name, "$s") { // TODO: better detect swift symbols
										i.Payload.ProcessByPid[pid].ThreadByID[tid].UserFrames[idx].Symbol, _ = swift.Demangle(fn.Name)
									} else if strings.HasPrefix(fn.Name, "__Z") || strings.HasPrefix(fn.Name, "_Z") {
										i.Payload.ProcessByPid[pid].ThreadByID[tid].UserFrames[idx].Symbol = demangle.Do(fn.Name, false, false)
									} else {
										i.Payload.ProcessByPid[pid].ThreadByID[tid].UserFrames[idx].Symbol = fn.Name
									}
								} else {
									i.Payload.ProcessByPid[pid].ThreadByID[tid].UserFrames[idx].Symbol = fn.Name
								}
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
			for idx, frame := range thread.KernelFrames {
				i.Payload.ProcessByPid[pid].ThreadByID[tid].KernelFrames[idx].ImageOffset += i.Payload.BinaryImages[frame.ImageIndex].Base
				if len(i.Payload.BinaryImages[frame.ImageIndex].Name) > 0 {
					i.Payload.ProcessByPid[pid].ThreadByID[tid].KernelFrames[idx].ImageName = i.Payload.BinaryImages[frame.ImageIndex].Name
				} else {
					if strings.HasPrefix(i.Payload.ProcessByPid[pid].ThreadByID[tid].KernelFrames[idx].ImageName, "image_") {
						i.Payload.ProcessByPid[pid].ThreadByID[tid].KernelFrames[idx].ImageName += " (maybe a kext)"
					}
				}
				if i.Payload.ProcessByPid[pid].ThreadByID[tid].KernelFrames[idx].ImageName == "kernelcache" {
					// TODO: symbolicate kernelcache
					// i.Payload.ProcessByPid[pid].ThreadByID[tid].KernelFrames[idx].Slide =
				}
			}
		}
	}

	f.Close()

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
	case "Panic", "210":
		out = fmt.Sprintf("[%s] - %s - %s %s\n\n", colorTime(i.Header.Timestamp.Format("02Jan2006 15:04:05")), colorError(i.Header.BugTypeDesc), i.Payload.Product, i.Payload.Build)
		p210, err := parsePanicString210(i.Payload.PanicString)
		if err != nil {
			out += i.Payload.PanicString
		} else {
			out += p210.String()
		}
		out += fmt.Sprintf("%s: %s\n", colorField("Panic Flags"), i.Payload.PanicFlags)
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
			if p.ID == p210.PanickedTask.PID {
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
					} else {
						continue
					}
				}
			}
			out += fmt.Sprintf(colorField("Process")+": %s [%s]%s\n", colorImage(p.Name), colorBold("%d", p.ID), paniced)
			for _, t := range p.ThreadByID {
				paniced = ""
				if t.ID == p210.PanickedThread.TID {
					paniced = colorError("       (Panicked)")
				} else {
					/* filter threads */
					if !i.Config.All {
						if i.Config.Running {
							if !slices.Contains(t.State, "TH_RUN") {
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
					buf := bytes.NewBufferString("")
					w := tabwriter.NewWriter(buf, 0, 0, 1, ' ', 0)
					for idx, f := range t.UserFrames {
						slide := ""
						if f.Slide > 0 {
							slide = fmt.Sprintf(" (slide %#x)", f.Slide)
						}
						symloc := ""
						if f.SymbolLocation > 0 {
							symloc = fmt.Sprintf(" + %d", f.SymbolLocation)
						}
						fmt.Fprintf(w, "      %02d: %s\t%s%s %s%s\n", idx, colorImage(f.ImageName), colorAddr("%#x", f.ImageOffset), slide, colorField(f.Symbol), symloc)
					}
					w.Flush()
					out += buf.String()
				}
				if len(t.KernelFrames) > 0 {
					out += "    Kernel Frames:\n"
					buf := bytes.NewBufferString("")
					w := tabwriter.NewWriter(buf, 0, 0, 1, ' ', 0)
					for idx, f := range t.KernelFrames {
						slide := ""
						if p210.KernelCacheSlide != nil && p210.KernelCacheSlide.Value.(uint64) > 0 && f.ImageName == "kernelcache" {
							slide = fmt.Sprintf(" (slide %#x)", p210.KernelCacheSlide.Value.(uint64))
						}
						if p210.KernelSlide != nil && p210.KernelSlide.Value.(uint64) > 0 && (f.ImageName == "kernelcache" || f.ImageName == "kernel") {
							slide = fmt.Sprintf(" (slide %#x)", p210.KernelSlide.Value.(uint64))
						}
						symloc := ""
						if f.SymbolLocation > 0 {
							symloc = fmt.Sprintf(" + %d", f.SymbolLocation)
						}
						fmt.Fprintf(w, "      %02d: %s\t%s%s %s%s\n", idx, colorImage(f.ImageName), colorAddr("%#x", f.ImageOffset), slide, colorField(f.Symbol), symloc)
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
		out += fmt.Sprintf("\n%s:      %s (%s) %s\n", colorField("Exception Type"), colorBold(i.Payload.Exception.Type), i.Payload.Exception.Signal, i.Payload.Exception.Message)
		if len(i.Payload.Exception.Subtype) > 0 {
			out += fmt.Sprintf(colorField("Exception Subtype")+":   %s\n", i.Payload.Exception.Subtype)
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
					symloc := ""
					if f.SymbolLocation > 0 {
						symloc = fmt.Sprintf(" + %d", f.SymbolLocation)
					}
					fmt.Fprintf(w, "  %02d: %s\t%s %s%s\n", idx, colorImage(i.Payload.UsedImages[f.ImageIndex].Name), colorAddr("%#x", i.Payload.UsedImages[f.ImageIndex].Base+f.ImageOffset), colorField(f.Symbol), symloc)
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
				symloc := ""
				if f.SymbolLocation > 0 {
					symloc = fmt.Sprintf(" + %d", f.SymbolLocation)
				}
				fmt.Fprintf(w, "  %02d: %s\t%s %s%s\n", idx, colorImage(i.Payload.UsedImages[f.ImageIndex].Name), colorAddr("%#x", i.Payload.UsedImages[f.ImageIndex].Base+f.ImageOffset), colorField(f.Symbol), symloc)
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
