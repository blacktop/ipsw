package crashlog

import (
	"bytes"
	"compress/gzip"
	_ "embed"
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"
	"text/tabwriter"
	"time"
)

//go:embed data/log_type.gz
var logTypeData []byte

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
	SystemTimeTask      int            `json:"systemTimeTask"`
	Flags               []string       `json:"flags"`
	ResidentMemoryBytes int            `json:"residentMemoryBytes"`
	ThreadByID          map[int]Thread `json:"threadById,omitempty"`
}

type Thread struct {
	ID                 int       `json:"id"`
	Name               string    `json:"name,omitempty"`
	State              []string  `json:"state"`
	Continuation       []int     `json:"continuation,omitempty"`
	Queue              string    `json:"queue,omitempty"`
	DispatchQueueLabel string    `json:"dispatch_queue_label,omitempty"`
	SchedFlags         []string  `json:"schedFlags,omitempty"`
	BasePriority       int       `json:"basePriority"`
	UserFrames         [][]int   `json:"userFrames"`
	KernelFrames       [][]int   `json:"kernelFrames,omitempty"`
	WaitEvent          []float64 `json:"waitEvent,omitempty"`
	QosRequested       string    `json:"qosRequested,omitempty"`
	QosEffective       string    `json:"qosEffective,omitempty"`
	UserTime           float64   `json:"userTime"`
	UserUsec           int       `json:"user_usec"`
	SystemTime         int       `json:"systemTime"`
	SystemUsec         int       `json:"system_usec"`
	SchedPriority      int       `json:"schedPriority"`
}

type BinaryImage struct {
	UUID   string  `json:"uuid,omitempty"`
	Base   float64 `json:"base,omitempty"`
	Source string  `json:"source,omitempty"`
}

func (bi *BinaryImage) UnmarshalJSON(b []byte) error {
	var s [3]any
	if err := json.Unmarshal(b, &s); err != nil {
		return err
	}
	*bi = BinaryImage{
		UUID: s[0].(string),
		Base: s[1].(float64),
	}
	switch s[2].(string) {
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
		return fmt.Errorf("invalid binary image source: %v", s[2])
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
	Value             float64 `json:"value,omitempty"`
	SymbolLocation    int     `json:"symbolLocation,omitempty"`
	Symbol            string  `json:"symbol,omitempty"`
	Description       string  `json:"description,omitempty"`
	MatchesCrashFrame int     `json:"matchesCrashFrame,omitempty"`
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

func (s ThreadState) String() string {
	return fmt.Sprintf(
		"    x0: %#016x   x1: %#016x   x2: %#016x   x3: %#016x\n"+
			"    x4: %#016x   x5: %#016x   x6: %#016x   x7: %#016x\n"+
			"    x8: %#016x   x9: %#016x  x10: %#016x  x11: %#016x\n"+
			"   x12: %#016x  x13: %#016x  x14: %#016x  x15: %#016x\n"+
			"   x16: %#016x  x17: %#016x  x18: %#016x  x19: %#016x\n"+
			"   x20: %#016x  x21: %#016x  x22: %#016x  x23: %#016x\n"+
			"   x24: %#016x  x25: %#016x  x26: %#016x  x27: %#016x\n"+
			"   x28: %#016x   fp: %#016x   lr: %#016x\n"+
			"    sp: %#016x   pc: %#016x cpsr: %#08x\n"+
			"   esr: %#08x\n",
		int64(s.X[0].Value), int64(s.X[1].Value), int64(s.X[2].Value), int64(s.X[3].Value),
		int64(s.X[4].Value), int64(s.X[5].Value), int64(s.X[6].Value), int64(s.X[7].Value),
		int64(s.X[8].Value), int64(s.X[9].Value), int64(s.X[10].Value), int64(s.X[11].Value),
		int64(s.X[12].Value), int64(s.X[13].Value), int64(s.X[14].Value), int64(s.X[15].Value),
		int64(s.X[16].Value), int64(s.X[17].Value), int64(s.X[18].Value), int64(s.X[19].Value),
		int64(s.X[20].Value), int64(s.X[21].Value), int64(s.X[22].Value), int64(s.X[23].Value),
		int64(s.X[24].Value), int64(s.X[25].Value), int64(s.X[26].Value), int64(s.X[27].Value),
		int64(s.X[28].Value), int64(s.FP.Value), int64(s.LR.Value),
		int64(s.SP.Value), int64(s.PC.Value), int64(s.CPSR.Value),
		int64(s.ESR.Value))
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
	ImageIndex     int    `json:"imageIndex,omitempty"`
	ImageOffset    int    `json:"imageOffset,omitempty"`
	Symbol         string `json:"symbol,omitempty"`
	SymbolLocation int    `json:"symbolLocation,omitempty"`
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
		Base   int64  `json:"base,omitempty"`
		Name   string `json:"name,omitempty"`
		Path   string `json:"path,omitempty"`
		Size   int    `json:"size,omitempty"`
		Source string `json:"source,omitempty"`
		UUID   string `json:"uuid,omitempty"`
	} `json:"usedImages,omitempty"`
	SharedCache struct {
		Base int64  `json:"base,omitempty"`
		Size int64  `json:"size,omitempty"`
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

	return &ips, nil
}

func (i *Ips) String() string {
	var out string

	db, err := GetLogTypes()
	if err != nil {
		return "failed to get log types: " + err.Error()
	}

	if bt, ok := (*db)[i.Header.BugType]; ok {
		i.Header.BugType = bt.Name
		if len(bt.Comment) > 0 {
			i.Header.BugType += " (" + bt.Comment + ")"
		}
	}

	switch i.Header.BugType {
	case "Panic":
		out = fmt.Sprintf("[%s] - %s - %s %s\n\n", i.Header.Timestamp.Format("02Jan2006 15:04:05"), i.Header.BugType, i.Payload.Product, i.Payload.Build)
		out += i.Payload.PanicString
		out += i.Payload.OtherString + "\n"
		var pids []int
		for pid := range i.Payload.ProcessByPid {
			pids = append(pids, pid)
		}
		sort.Ints(pids)
		for pid := range pids {
			p := i.Payload.ProcessByPid[pid]
			out += fmt.Sprintf("Process: %s [%d]\n", p.Name, p.ID)
			for _, t := range p.ThreadByID {
				out += fmt.Sprintf("  Thread %d", t.ID)
				if len(t.Name) > 0 {
					out += fmt.Sprintf(" name: %s", t.Name)
					if len(t.DispatchQueueLabel) > 0 {
						out += ","
					}
				}
				if len(t.DispatchQueueLabel) > 0 {
					out += fmt.Sprintf(" queue: %s", t.DispatchQueueLabel)
				}
				out += "\n"
				out += fmt.Sprintf("    User Time: %f (%d)\n", t.UserTime, t.UserUsec)
				out += fmt.Sprintf("    System Time: %d (%d)\n", t.SystemTime, t.SystemUsec)
				out += fmt.Sprintf("    Base Priority: %d\n", t.BasePriority)
				out += fmt.Sprintf("    State: %s\n", t.State)
				if len(t.UserFrames) > 0 {
					out += "    User Frames:\n"
					for idx, f := range t.UserFrames {
						out += fmt.Sprintf("      %02d: %v\n", idx, f)
					}
				}
				if len(t.KernelFrames) > 0 {
					out += "    Kernel Frames:\n"
					for idx, f := range t.KernelFrames {
						out += fmt.Sprintf("      %02d: %v\n", idx, f)
					}
				}
			}
			out += "\n"
		}
	case "Crash":
		out = fmt.Sprintf("[%s] - %s\n\n", i.Header.Timestamp.Format("02Jan2006 15:04:05"), i.Header.BugType)
		out += fmt.Sprintf(
			"Process:             %s [%d]\n"+
				"Hardware Model:      %s\n"+
				"OS Version:          %s\n"+
				"BuildID:             %s\n"+
				"LockdownMode:        %d\n",
			i.Payload.ProcName,
			i.Payload.PID,
			i.Payload.ModelCode,
			i.Payload.OsVersion.Train,
			i.Payload.OsVersion.Build,
			i.Payload.LockdownMode)
		if i.Payload.SharedCache.Size > 0 {
			out += fmt.Sprintf("Shared Cache:        %s base: %#x size: %d\n", i.Payload.SharedCache.UUID, i.Payload.SharedCache.Base, i.Payload.SharedCache.Size)
		}
		out += fmt.Sprintf("\nException Type:      %s (%s) %s\n", i.Payload.Exception.Type, i.Payload.Exception.Signal, i.Payload.Exception.Message)
		if len(i.Payload.Exception.Subtype) > 0 {
			out += fmt.Sprintf("Exception Subtype:   %s\n", i.Payload.Exception.Subtype)
		}
		if len(i.Payload.VmRegionInfo) > 0 {
			out += fmt.Sprintf("VM Region Info: %s\n", i.Payload.VmRegionInfo)
		}
		if i.Payload.Asi != nil {
			out += "ASI:\n"
			for k, v := range i.Payload.Asi {
				out += fmt.Sprintf("    %s:\n", k)
				for _, s := range v {
					out += fmt.Sprintf("      - %s\n", s)
				}
			}
			out += "\n"
		}
		for _, t := range i.Payload.Threads {
			out += fmt.Sprintf("Thread %d:", t.ID)
			if len(t.Name) > 0 {
				out += fmt.Sprintf(" name: %s", t.Name)
				if len(t.Queue) > 0 {
					out += ","
				}
			}
			if len(t.Queue) > 0 {
				out += fmt.Sprintf(" queue: %s", t.Queue)
			}
			if t.Triggered {
				out += " (Crashed)\n"
			} else {
				out += "\n"
			}
			if len(t.Frames) > 0 {
				buf := bytes.NewBufferString("")
				w := tabwriter.NewWriter(buf, 0, 0, 1, ' ', 0)
				for idx, f := range t.Frames {
					fmt.Fprintf(w, "  %02d: %s\t%#x %s + %d\n", idx, i.Payload.UsedImages[f.ImageIndex].Name, i.Payload.UsedImages[f.ImageIndex].Base+int64(f.ImageOffset), f.Symbol, f.SymbolLocation)
				}
				w.Flush()
				out += buf.String()
			}
			if t.Triggered {
				out += fmt.Sprintf("Thread State:\n%s", t.ThreadState)
			}
			out += "\n"
		}
		if len(i.Payload.LastExceptionBacktrace) > 0 {
			out += "Last Exception Backtrace:\n"
			buf := bytes.NewBufferString("")
			w := tabwriter.NewWriter(buf, 0, 0, 1, ' ', 0)
			for idx, f := range i.Payload.LastExceptionBacktrace {
				fmt.Fprintf(w, "  %02d: %s\t%#x %s + %d\n", idx, i.Payload.UsedImages[f.ImageIndex].Name, i.Payload.UsedImages[f.ImageIndex].Base+int64(f.ImageOffset), f.Symbol, f.SymbolLocation)
			}
			w.Flush()
			out += buf.String() + "\n"
		}
		if len(i.Payload.VMSummary) > 0 {
			out += fmt.Sprintf("VM Summary: %s\n", i.Payload.VMSummary)
		}
	default:
		return fmt.Sprintf("%s: (unsupported, notify author)", i.Header.BugType)
	}

	return out
}
