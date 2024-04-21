package crashlog

import (
	"bytes"
	"compress/gzip"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/blacktop/go-macho"
	"github.com/blacktop/go-macho/types"
	"github.com/blacktop/ipsw/internal/commands/dsc"
	"github.com/blacktop/ipsw/internal/search"
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
var colorImage = color.New(color.Bold, color.FgHiMagenta).SprintFunc()
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

type Ips struct {
	Header  IpsMetadata
	Payload IPSPayload
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
}

type StoreInfo struct {
	ApplicationVariant        string `json:"applicationVariant,omitempty"`
	DeviceIdentifierForVendor string `json:"deviceIdentifierForVendor,omitempty"`
	ItemID                    string `json:"itemID,omitempty"`
}

type Exception struct {
	Codes    string `json:"codes,omitempty"`
	RawCodes []int  `json:"rawCodes,omitempty"`
	Message  string `json:"message,omitempty"`
	Signal   string `json:"signal,omitempty"`
	Type     string `json:"type,omitempty"`
	Subtype  string `json:"subtype,omitempty"`
}

type Register struct {
	Value             uint64 `json:"value,omitempty"`
	SymbolLocation    uint64 `json:"symbolLocation,omitempty"`
	Symbol            string `json:"symbol,omitempty"`
	Description       string `json:"description,omitempty"`
	MatchesCrashFrame int    `json:"matchesCrashFrame,omitempty"`
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

func (s ThreadState) String() string {
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
		fmtAddrSmol(s.ESR.Value), colorError(s.ESR.Description))
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
	SymbolLocation int    `json:"symbolLocation,omitempty"`
}

type PanicFrame struct {
	ImageIndex     uint64 `json:"imageIndex,omitempty"`
	ImageName      string `json:"imageName,omitempty"`
	ImageOffset    uint64 `json:"imageOffset,omitempty"`
	Symbol         string `json:"symbol,omitempty"`
	SymbolLocation int    `json:"symbolLocation,omitempty"`
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
	IsCorpse               bool         `json:"isCorpse,omitempty"`
	IsNonFatal             string       `json:"isNonFatal,omitempty"`
	IsSimulated            string       `json:"isSimulated,omitempty"`
	Uptime                 int          `json:"uptime,omitempty"`
	Translated             bool         `json:"translated,omitempty"`
	ProcName               string       `json:"procName,omitempty"`
	ProcPath               string       `json:"procPath,omitempty"`
	ProcRole               string       `json:"procRole,omitempty"`
	UserID                 int          `json:"userID,omitempty"`
	DeployVersion          int          `json:"deployVersion,omitempty"`
	ModelCode              string       `json:"modelCode,omitempty"`
	CoalitionID            int          `json:"coalitionID,omitempty"`
	OsVersion              OsVersion    `json:"osVersion,omitempty"`
	CaptureTime            string       `json:"captureTime,omitempty"`
	PID                    int          `json:"pid,omitempty"`
	CPUType                string       `json:"cpuType,omitempty"`
	RootsInstalled         int          `json:"roots_installed,omitempty"`
	BugType                string       `json:"bug_type,omitempty"`
	ProcLaunch             string       `json:"procLaunch,omitempty"`
	ProcStartAbsTime       int64        `json:"procStartAbsTime,omitempty"`
	ProcExitAbsTime        int64        `json:"procExitAbsTime,omitempty"`
	BundleInfo             BundleInfo   `json:"bundleInfo,omitempty"`
	StoreInfo              StoreInfo    `json:"storeInfo,omitempty"`
	ParentProc             string       `json:"parentProc,omitempty"`
	ParentPid              int          `json:"parentPid,omitempty"`
	CoalitionName          string       `json:"coalitionName,omitempty"`
	LockdownMode           int          `json:"ldm,omitempty"`
	WasUnlockedSinceBoot   int          `json:"wasUnlockedSinceBoot,omitempty"`
	IsLocked               int          `json:"isLocked,omitempty"`
	ThrottleTimeout        int64        `json:"throttleTimeout,omitempty"`
	BasebandVersion        string       `json:"basebandVersion,omitempty"`
	Exception              Exception    `json:"exception,omitempty"`
	LastExceptionBacktrace []Frame      `json:"lastExceptionBacktrace,omitempty"`
	FaultingThread         int          `json:"faultingThread,omitempty"`
	Threads                []UserThread `json:"threads,omitempty"`
	UsedImages             []struct {
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

func OpenIPS(in string) (*Ips, error) {
	var ips Ips

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
		case "KernelCache":
			i.Payload.BinaryImages[idx].Name = "kernelcache"
			total--
		case "SharedCache":
			i.Payload.BinaryImages[idx].Name = "dyld_shared_cache"
			total--
		}
	}

	machoFuncMap := make(map[string][]types.Function)
	if err := search.ForEachMachoInIPSW(ipswPath, func(path string, m *macho.File) error {
		if total == 0 {
			return ErrDone // break
		}
		for idx, img := range i.Payload.BinaryImages {
			var slide uint64
			if strings.EqualFold(img.UUID, m.UUID().UUID.String()) {
				i.Payload.BinaryImages[idx].Path = path
				i.Payload.BinaryImages[idx].Name = path
				slide = i.Payload.BinaryImages[idx].Base - m.GetBaseAddress()
				// i.Payload.BinaryImages[idx].Name = filepath.Base(path)
				for _, fn := range m.GetFunctions() {
					if syms, err := m.FindAddressSymbols(fn.StartAddr); err == nil {
						for _, sym := range syms {
							fn.Name = sym.Name
						}
						fn.StartAddr += slide
						fn.EndAddr += slide
						machoFuncMap[i.Payload.BinaryImages[idx].Name] = append(machoFuncMap[i.Payload.BinaryImages[idx].Name], fn)
					} else {
						fn.StartAddr += slide
						fn.EndAddr += slide
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
				if len(i.Payload.BinaryImages[frame.ImageIndex].Name) > 0 {
					i.Payload.ProcessByPid[pid].ThreadByID[tid].UserFrames[idx].ImageName = i.Payload.BinaryImages[frame.ImageIndex].Name
				}
				i.Payload.ProcessByPid[pid].ThreadByID[tid].UserFrames[idx].ImageOffset += i.Payload.BinaryImages[frame.ImageIndex].Base
				if i.Payload.ProcessByPid[pid].ThreadByID[tid].UserFrames[idx].ImageName == "dyld_shared_cache" {
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
								delta := ""
								if i.Payload.ProcessByPid[pid].ThreadByID[tid].UserFrames[idx].ImageOffset-fn.StartAddr != 0 {
									delta = fmt.Sprintf(" + %d", i.Payload.ProcessByPid[pid].ThreadByID[tid].UserFrames[idx].ImageOffset-fn.StartAddr)
								}
								i.Payload.ProcessByPid[pid].ThreadByID[tid].UserFrames[idx].Symbol = sym + delta
							} else {
								i.Payload.ProcessByPid[pid].ThreadByID[tid].UserFrames[idx].Symbol = fmt.Sprintf("func_%x", fn.StartAddr)
							}
						}
					}
				} else {
					// lookup symbol in MachO symbol map
					if funcs, ok := machoFuncMap[i.Payload.ProcessByPid[pid].ThreadByID[tid].UserFrames[idx].ImageName]; ok {
						for _, fn := range funcs {
							if fn.StartAddr <= i.Payload.ProcessByPid[pid].ThreadByID[tid].UserFrames[idx].ImageOffset && i.Payload.ProcessByPid[pid].ThreadByID[tid].UserFrames[idx].ImageOffset < fn.EndAddr {
								delta := ""
								if i.Payload.ProcessByPid[pid].ThreadByID[tid].UserFrames[idx].ImageOffset-fn.StartAddr != 0 {
									delta = fmt.Sprintf(" + %d", i.Payload.ProcessByPid[pid].ThreadByID[tid].UserFrames[idx].ImageOffset-fn.StartAddr)
								}
								i.Payload.ProcessByPid[pid].ThreadByID[tid].UserFrames[idx].Symbol = fn.Name + delta
							}
						}
					}
				}
			}
			for idx, frame := range thread.KernelFrames {
				if len(i.Payload.BinaryImages[frame.ImageIndex].Name) > 0 {
					i.Payload.ProcessByPid[pid].ThreadByID[tid].KernelFrames[idx].ImageName = i.Payload.BinaryImages[frame.ImageIndex].Name
				}
				i.Payload.ProcessByPid[pid].ThreadByID[tid].KernelFrames[idx].ImageOffset += i.Payload.BinaryImages[frame.ImageIndex].Base
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

func (i *Ips) String(verbose bool) string {
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
				if !verbose {
					continue
				}
			}
			out += fmt.Sprintf(colorField("Process")+": %s [%s]%s\n", colorImage(p.Name), colorBold("%d", p.ID), paniced)
			for _, t := range p.ThreadByID {
				paniced = ""
				if t.ID == p210.PanickedThread.TID {
					paniced = colorError("       (Panicked)")
				} else {
					if !verbose {
						continue
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
						symloc := ""
						if f.SymbolLocation > 0 {
							symloc = fmt.Sprintf(" + %d", f.SymbolLocation)
						}
						fmt.Fprintf(w, "      %02d: %s\t%s %s%s\n", idx, colorImage(f.ImageName), colorAddr("%#x", f.ImageOffset), colorField(f.Symbol), colorBold(symloc))
					}
					w.Flush()
					out += buf.String()
				}
				if len(t.KernelFrames) > 0 {
					out += "    Kernel Frames:\n"
					buf := bytes.NewBufferString("")
					w := tabwriter.NewWriter(buf, 0, 0, 1, ' ', 0)
					for idx, f := range t.KernelFrames {
						symloc := ""
						if f.SymbolLocation > 0 {
							symloc = fmt.Sprintf(" + %d", f.SymbolLocation)
						}
						fmt.Fprintf(w, "      %02d: %s\t%s %s%s\n", idx, colorImage(f.ImageName), colorAddr("%#x", f.ImageOffset), colorField(f.Symbol), colorBold(symloc))
					}
					w.Flush()
					out += buf.String()
				}
			}
			out += "\n"
		}
	case "Crash", "309":
		out = fmt.Sprintf("[%s] - %s\n\n", colorTime(i.Header.Timestamp.Format("02Jan2006 15:04:05")), colorError(i.Header.BugTypeDesc))
		out += fmt.Sprintf(
			colorField("Process")+":             %s [%d]\n"+
				colorField("Hardware Model")+":      %s\n"+
				colorField("OS Version")+":          %s\n"+
				colorField("BuildID")+":             %s\n"+
				colorField("LockdownMode")+":        %d\n",
			i.Payload.ProcName, i.Payload.PID,
			i.Payload.ModelCode,
			i.Payload.OsVersion.Train,
			i.Payload.OsVersion.Build,
			i.Payload.LockdownMode)
		if i.Payload.SharedCache.Size > 0 {
			out += fmt.Sprintf(colorField("Shared Cache")+":        %s %s: %#x %s: %d\n", i.Payload.SharedCache.UUID, colorField("base"), i.Payload.SharedCache.Base, colorField("size"), i.Payload.SharedCache.Size)
		}
		out += fmt.Sprintf("\n%s:      %s (%s) %s\n", colorField("Exception Type"), i.Payload.Exception.Type, i.Payload.Exception.Signal, i.Payload.Exception.Message)
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
					fmt.Fprintf(w, "  %02d: %s\t%s %s%s\n", idx, colorImage(i.Payload.UsedImages[f.ImageIndex].Name), colorAddr("%#x", i.Payload.UsedImages[f.ImageIndex].Base+f.ImageOffset), colorField(f.Symbol), colorBold(symloc))
				}
				w.Flush()
				out += buf.String()
			}
			if t.Triggered {
				out += colorField("Thread") + colorBold(" %d ", t.ID) + colorField(t.ThreadState.Flavor) + "\n" + t.ThreadState.String()
			}
			out += "\n"
		}
		if len(i.Payload.LastExceptionBacktrace) > 0 {
			out += colorField("Last Exception Backtrace") + ":\n"
			buf := bytes.NewBufferString("")
			w := tabwriter.NewWriter(buf, 0, 0, 1, ' ', 0)
			for idx, f := range i.Payload.LastExceptionBacktrace {
				fmt.Fprintf(w, "  %02d: %s\t%s %s + %d\n", idx, colorImage(i.Payload.UsedImages[f.ImageIndex].Name), colorAddr("%#x", i.Payload.UsedImages[f.ImageIndex].Base+f.ImageOffset), colorField(f.Symbol), f.SymbolLocation)
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
