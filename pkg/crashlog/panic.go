package crashlog

import (
	"bufio"
	"fmt"
	"regexp"
	"strings"

	"github.com/apex/log"
	"github.com/spf13/cast"
)

type EpochTimeSec struct {
	Sec  uint64
	Usec uint64
}

func (e EpochTimeSec) String() string {
	return fmt.Sprintf("%#08x %#08x", e.Sec, e.Usec)
}

type EpochTime struct {
	Boot     EpochTimeSec
	Sleep    EpochTimeSec
	Wake     EpochTimeSec
	Calendar EpochTimeSec
}

func (e EpochTime) String() string {
	return fmt.Sprintf(
		colorField("Epoch Time         sec       usec\n")+
			colorImage("  Boot    ")+": %s\n"+
			colorImage("  Sleep   ")+": %s\n"+
			colorImage("  Wake    ")+": %s\n"+
			colorImage("  Calendar")+": %s\n",
		e.Boot,
		e.Sleep,
		e.Wake,
		e.Calendar)
}

type Range struct {
	Start uint64
	End   uint64
}

func (r Range) String() string {
	return fmt.Sprintf("%#016x - %#016x", r.Start, r.End)
}

type ZoneInfo struct {
	ZoneMap  Range
	VM       Range
	RO       Range
	Gen0     Range
	Gen1     Range
	Gen2     Range
	Gen3     Range
	Data     Range
	Metadata Range
	Bitmaps  Range
	Extra    Range
}

func (z ZoneInfo) String() string {
	return fmt.Sprintf(
		colorField("Zone Info\n")+
			colorImage("  Zone Map")+": %s\n"+
			colorImage("  . VM    ")+": %s\n"+
			colorImage("  . RO    ")+": %s\n"+
			colorImage("  . GEN0  ")+": %s\n"+
			colorImage("  . GEN1  ")+": %s\n"+
			colorImage("  . GEN2  ")+": %s\n"+
			colorImage("  . GEN3  ")+": %s\n"+
			colorImage("  . DATA  ")+": %s\n"+
			colorImage("  Metadata")+": %s\n"+
			colorImage("  Bitmaps ")+": %s\n"+
			colorImage("  Extra   ")+": %s\n",
		z.ZoneMap,
		z.VM,
		z.RO,
		z.Gen0,
		z.Gen1,
		z.Gen2,
		z.Gen3,
		z.Data,
		z.Metadata,
		z.Bitmaps,
		z.Extra)
}

type TPIDRx_ELy map[string]uint64

func (t TPIDRx_ELy) String() string {
	tpidrx := ""
	for key, val := range t {
		tpidrx += fmt.Sprintf(colorImage("    %-3s")+": %#016x\n", key, val)
	}
	return fmt.Sprintf(colorField("TPIDRx_ELy")+"\n%s", tpidrx)
}

type Core struct {
	Num int
	Msg string
	PC  uint64
	LR  uint64
	FP  uint64
}

func (c Core) String() string {
	if len(c.Msg) > 0 {
		return fmt.Sprintf(colorField("CORE")+" %d  %s", c.Num, c.Msg)
	}
	return fmt.Sprintf(colorField("CORE")+" %d"+colorField(": PC")+"=%#016x, "+colorField("LR")+"=%#016x, "+colorField("FP")+"=%#016x", c.Num, c.PC, c.LR, c.FP)
}

type PanickedTask struct {
	PID     int
	Name    string
	Address uint64
	Pages   int
	Threads int
}

func (p PanickedTask) String() string {
	return fmt.Sprintf(colorField("Panicked Task")+":   %#016x, %d "+colorField("pages")+", %d "+colorField("threads")+", "+colorField("pid")+" %d: "+colorImage("%s"), p.Address, p.Pages, p.Threads, p.PID, p.Name)
}

type State struct {
	LR uint64
	FP uint64
}

func (s State) String() string {
	return fmt.Sprintf(colorImage("lr")+": %#016x - "+colorImage("fp")+": %#016x", s.LR, s.FP)
}

type PanickedThread struct {
	TID       int
	Backtrace uint64
	Address   uint64
	CallStack []State
}

func (p PanickedThread) String() string {
	callstack := "\n"
	for _, state := range p.CallStack {
		callstack += fmt.Sprintf("    %s\n", state)
	}
	return fmt.Sprintf(colorField("Panicked Thread")+": %#016x, "+colorField("backtrace")+": %#016x, "+colorField("tid")+": %d%s", p.Address, p.Backtrace, p.TID, callstack)
}

type Panic210 struct {
	Panic            string
	DebuggerMessage  string
	MemoryID         uint64
	OsReleaseType    string
	OsVersion        string
	KernelVersion    string
	KernelCacheUUID  string
	KernelUUID       string
	BootSessionUUID  string
	IBootVersion     string
	SecureBoot       bool
	RootsInstalled   bool
	PaniclogVersion  string
	KernelSlide      uint64
	KernelTextBase   uint64
	MachAbsoluteTime uint64

	EpochTime EpochTime

	ZoneInfo ZoneInfo

	TPIDRx_ELy TPIDRx_ELy

	Cores []Core

	CompressorInfo string
	PanickedTask   PanickedTask
	PanickedThread PanickedThread

	lines []string
}

func parsePanicString210(in string) (*Panic210, error) {
	var err error

	crash := &Panic210{}

	scanner := bufio.NewScanner(strings.NewReader(in))
	for scanner.Scan() {
		crash.lines = append(crash.lines, scanner.Text())
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("failed to scan panic string: %v", err)
	}

	crash.Panic = crash.lines[0]

	crash.DebuggerMessage, err = crash.getStrField("Debugger message: ")
	if err != nil {
		log.WithError(err).Error("failed to get debugger message")
	}
	crash.MemoryID, err = crash.getIntField("Memory ID: ")
	if err != nil {
		log.WithError(err).Error("failed to get memory ID")
	}
	crash.OsReleaseType, err = crash.getStrField("OS release type: ")
	if err != nil {
		log.WithError(err).Error("failed to get OS release type")
	}
	crash.OsVersion, err = crash.getStrField("OS version: ")
	if err != nil {
		log.WithError(err).Error("failed to get OS version")
	}
	crash.KernelVersion, err = crash.getStrField("Kernel version: ")
	if err != nil {
		log.WithError(err).Error("failed to get kernel version")
	}
	crash.KernelCacheUUID, err = crash.getStrField("KernelCache UUID: ")
	if err != nil {
		log.WithError(err).Error("failed to get kernel cache UUID")
	}
	crash.KernelUUID, err = crash.getStrField("Kernel UUID: ")
	if err != nil {
		log.WithError(err).Error("failed to get kernel UUID")
	}
	crash.BootSessionUUID, err = crash.getStrField("Boot session UUID: ")
	if err != nil {
		log.WithError(err).Error("failed to get boot session UUID")
	}
	crash.IBootVersion, err = crash.getStrField("iBoot version: ")
	if err != nil {
		log.WithError(err).Error("failed to get iBoot version")
	}
	crash.SecureBoot, err = crash.getBoolField("secure boot?: ")
	if err != nil {
		log.WithError(err).Error("failed to get secure boot")
	}
	crash.RootsInstalled, err = crash.getBoolField("roots installed: ")
	if err != nil {
		log.WithError(err).Error("failed to get roots installed")
	}
	crash.PaniclogVersion, err = crash.getStrField("Paniclog version: ")
	if err != nil {
		log.WithError(err).Error("failed to get paniclog version")
	}
	crash.KernelSlide, err = crash.getIntField("Kernel slide:      ")
	if err != nil {
		log.WithError(err).Error("failed to get kernel slide")
	}
	crash.KernelTextBase, err = crash.getIntField("Kernel text base:  ")
	if err != nil {
		log.WithError(err).Error("failed to get kernel text base")
	}
	crash.MachAbsoluteTime, err = crash.getIntField("mach_absolute_time: ")
	if err != nil {
		log.WithError(err).Error("failed to get mach absolute time")
	}
	if err := crash.getEpochTime(); err != nil {
		log.WithError(err).Error("failed to get epoch time")
	}
	if err := crash.getZoneInfo(); err != nil {
		log.WithError(err).Error("failed to get zone info")
	}
	if err := crash.getTPIDRx_ELy(); err != nil {
		log.WithError(err).Error("failed to get TPIDRx_ELy")
	}
	if err := crash.getCores(); err != nil {
		log.WithError(err).Error("failed to get cores")
	}
	crash.CompressorInfo, err = crash.getStrField("Compressor Info: ")
	if err != nil {
		log.WithError(err).Error("failed to get compressor info")
	}
	if err := crash.getPanickedTask(); err != nil {
		log.WithError(err).Error("failed to get panicked task")
	}
	if err := crash.getPanickedThread(); err != nil {
		log.WithError(err).Error("failed to get panicked thread")
	}
	return crash, nil
}

func (p *Panic210) getBoolField(key string) (bool, error) {
	for _, line := range p.lines {
		if strings.HasPrefix(line, key) {
			switch strings.ToLower(strings.TrimPrefix(line, key)) {
			case "yes", "1", "true":
				return true, nil
			case "no", "0", "false":
				return false, nil
			default:
				return false, fmt.Errorf("failed to parse bool: %s", line)
			}
		}
	}
	return false, fmt.Errorf("failed to find %s", key)
}
func (p *Panic210) getStrField(key string) (string, error) {
	for _, line := range p.lines {
		if strings.HasPrefix(line, key) {
			return strings.TrimPrefix(line, key), nil
		}
	}
	return "", fmt.Errorf("failed to find %s", key)
}
func (p *Panic210) getIntField(key string) (uint64, error) {
	for _, line := range p.lines {
		if strings.HasPrefix(line, key) {
			return cast.ToUint64(strings.TrimPrefix(line, key)), nil
		}
	}
	return 0, fmt.Errorf("failed to find %s", key)
}
func (p *Panic210) getEpochTime() (err error) {
	found := false

	parse := func(line string) (uint64, uint64, error) {
		timeRE := regexp.MustCompile(`: (?P<sec>0x\w+) (?P<usec>0x\w+)`)
		matches := timeRE.FindStringSubmatch(line)
		if len(matches) < 3 {
			return 0, 0, fmt.Errorf("failed to parse time: %s", line)
		}
		return cast.ToUint64(matches[1]), cast.ToUint64(matches[2]), nil
	}

	for _, line := range p.lines {
		if strings.HasPrefix(line, "Epoch Time:        sec       usec") {
			found = true
			continue
		}
		if found {
			if strings.HasPrefix(line, "  Boot    : ") {
				p.EpochTime.Boot.Sec, p.EpochTime.Boot.Usec, err = parse(line)
				if err != nil {
					return err
				}
				continue
			}
			if strings.HasPrefix(line, "  Sleep   : ") {
				p.EpochTime.Sleep.Sec, p.EpochTime.Sleep.Usec, err = parse(line)
				if err != nil {
					return err
				}
				continue
			}
			if strings.HasPrefix(line, "  Wake    :  ") {
				p.EpochTime.Wake.Sec, p.EpochTime.Wake.Usec, err = parse(line)
				if err != nil {
					return err
				}
				continue
			}
			if strings.HasPrefix(line, "  Calendar: ") {
				p.EpochTime.Calendar.Sec, p.EpochTime.Calendar.Usec, err = parse(line)
				if err != nil {
					return err
				}
				continue
			}
		}
	}

	if !found {
		return fmt.Errorf("failed to find Epoch Time")
	}

	return nil
}
func (p *Panic210) getZoneInfo() (err error) {
	found := false

	parse := func(line string) (uint64, uint64, error) {
		timeRE := regexp.MustCompile(`: (?P<start>\w+) - (?P<end>\w+)`)
		matches := timeRE.FindStringSubmatch(line)
		if len(matches) < 3 {
			return 0, 0, fmt.Errorf("failed to parse time: %s", line)
		}
		return cast.ToUint64(matches[1]), cast.ToUint64(matches[2]), nil
	}

	for _, line := range p.lines {
		if strings.HasPrefix(line, "Zone info:") {
			found = true
			continue
		}
		if found {
			if strings.HasPrefix(line, "  Zone map: ") {
				p.ZoneInfo.ZoneMap.Start, p.ZoneInfo.ZoneMap.End, err = parse(line)
				if err != nil {
					return err
				}
				continue
			}
			if strings.HasPrefix(line, "  . VM    : ") {
				p.ZoneInfo.VM.Start, p.ZoneInfo.VM.End, err = parse(line)
				if err != nil {
					return err
				}
				continue
			}
			if strings.HasPrefix(line, "  . RO    : ") {
				p.ZoneInfo.RO.Start, p.ZoneInfo.RO.End, err = parse(line)
				if err != nil {
					return err
				}
				continue
			}
			if strings.HasPrefix(line, "  . GEN0  : ") {
				p.ZoneInfo.Gen0.Start, p.ZoneInfo.Gen0.End, err = parse(line)
				if err != nil {
					return err
				}
				continue
			}
			if strings.HasPrefix(line, "  . GEN1  : ") {
				p.ZoneInfo.Gen1.Start, p.ZoneInfo.Gen1.End, err = parse(line)
				if err != nil {
					return err
				}
				continue
			}
			if strings.HasPrefix(line, "  . GEN2  : ") {
				p.ZoneInfo.Gen2.Start, p.ZoneInfo.Gen2.End, err = parse(line)
				if err != nil {
					return err
				}
				continue
			}
			if strings.HasPrefix(line, "  . GEN3  : ") {
				p.ZoneInfo.Gen3.Start, p.ZoneInfo.Gen3.End, err = parse(line)
				if err != nil {
					return err
				}
				continue
			}
			if strings.HasPrefix(line, "  . DATA  : ") {
				p.ZoneInfo.Data.Start, p.ZoneInfo.Data.End, err = parse(line)
				if err != nil {
					return err
				}
				continue
			}
			if strings.HasPrefix(line, "  Metadata: ") {
				p.ZoneInfo.Metadata.Start, p.ZoneInfo.Metadata.End, err = parse(line)
				if err != nil {
					return err
				}
				continue
			}
			if strings.HasPrefix(line, "  Bitmaps : ") {
				p.ZoneInfo.Bitmaps.Start, p.ZoneInfo.Bitmaps.End, err = parse(line)
				if err != nil {
					return err
				}
				continue
			}
			if strings.HasPrefix(line, "  Extra   : ") {
				p.ZoneInfo.Extra.Start, p.ZoneInfo.Extra.End, err = parse(line)
				if err != nil {
					return err
				}
				continue
			}
		}
	}

	if !found {
		return fmt.Errorf("failed to find Epoch Time")
	}

	return nil
}
func (p *Panic210) getTPIDRx_ELy() (err error) {
	re := regexp.MustCompile(`^TPIDRx_ELy`)
	p.TPIDRx_ELy = make(map[string]uint64)
	for _, line := range p.lines {
		if re.MatchString(line) {
			tpidRE := regexp.MustCompile(`(?:(?P<key>\w+): (?P<val>\w+)\s)+`)
			matches := tpidRE.FindAllStringSubmatch(line, -1)
			if len(matches) < 3 {
				continue
			}
			for _, match := range matches {
				p.TPIDRx_ELy[match[1]] = cast.ToUint64(match[2])
			}
			return nil
		}
	}
	return fmt.Errorf("failed to find TPIDRx_ELy")
}
func (p *Panic210) getCores() (err error) {
	re := regexp.MustCompile(`^CORE \d+`)
	for _, line := range p.lines {
		if re.MatchString(line) {
			coreRE := regexp.MustCompile(`^CORE (?P<core>\d+): PC=(?P<pc>0x\w+), LR=(?P<lr>0x\w+), FP=(?P<fp>0x\w+)`)
			matches := coreRE.FindStringSubmatch(line)
			if len(matches) < 5 {
				coreRE = regexp.MustCompile(`^CORE (?P<core>\d+) (?P<msg>.*)`)
				if matches = coreRE.FindStringSubmatch(line); len(matches) == 3 {
					core := Core{
						Num: cast.ToInt(matches[1]),
						Msg: matches[2],
					}
					p.Cores = append(p.Cores, core)
				}
				continue
			}
			core := Core{
				Num: cast.ToInt(matches[1]),
				PC:  cast.ToUint64(matches[2]),
				LR:  cast.ToUint64(matches[3]),
				FP:  cast.ToUint64(matches[4]),
			}
			p.Cores = append(p.Cores, core)
		}
	}
	return nil
}
func (p *Panic210) getPanickedTask() (err error) {
	re := regexp.MustCompile(`^Panicked task `)
	for _, line := range p.lines {
		if re.MatchString(line) {
			ptRE := regexp.MustCompile(`^Panicked task (?P<task>\w+): (?P<pages>\d+) pages, (?P<threads>\d+) threads: pid (?P<pid>\d+): (?P<name>.*)`)
			matches := ptRE.FindStringSubmatch(line)
			if len(matches) < 6 {
				continue
			}
			p.PanickedTask = PanickedTask{
				PID:     cast.ToInt(matches[4]),
				Name:    matches[5],
				Address: cast.ToUint64(matches[1]),
				Pages:   cast.ToInt(matches[2]),
				Threads: cast.ToInt(matches[3]),
			}
			return nil
		}
	}
	return fmt.Errorf("failed to find panicked task")
}
func (p *Panic210) getPanickedThread() (err error) {
	re := regexp.MustCompile(`^Panicked thread:`)
	found := false
	for _, line := range p.lines {
		if re.MatchString(line) {
			ptRE := regexp.MustCompile(`^Panicked thread: (?P<thread>\w+), backtrace: (?P<backtrace>\w+), tid: (?P<tid>\d+)`)
			matches := ptRE.FindStringSubmatch(line)
			if len(matches) < 4 {
				continue
			}
			p.PanickedThread = PanickedThread{
				Address:   cast.ToUint64(matches[1]),
				Backtrace: cast.ToUint64(matches[2]),
				TID:       cast.ToInt(matches[3]),
			}
			found = true
			continue
		}
		if found {
			csRE := regexp.MustCompile(`^\s+lr: (?P<lr>\w+)  fp: (?P<fp>\w+)`)
			matches := csRE.FindStringSubmatch(line)
			if len(matches) < 3 {
				continue
			}
			p.PanickedThread.CallStack = append(p.PanickedThread.CallStack, State{
				LR: cast.ToUint64(matches[1]),
				FP: cast.ToUint64(matches[2]),
			})
		}
	}
	if found {
		return nil
	}
	return fmt.Errorf("failed to find panicked thread")
}
func (p *Panic210) String() string {
	panicParts := strings.Split(p.Panic, ": ")
	var panic string
	for idx, part := range panicParts {
		if idx < len(panicParts)-1 {
			panic += fmt.Sprintf("%s%s\n", strings.Repeat("    ", idx), part+":")
		} else {
			panic += fmt.Sprintf("%s\n", part) // last part
		}
	}
	var cores string
	for _, core := range p.Cores {
		cores += fmt.Sprintf("%s\n", core)
	}
	return fmt.Sprintf(
		"%s\n"+
			colorField("Debugger Message")+":   %s\n"+
			colorField("Memory ID")+":          %d\n"+
			colorField("OS Release Type")+":    %s\n"+
			colorField("OS Version")+":         %s\n"+
			colorField("Kernel Version")+":     %s\n"+
			colorField("KernelCache UUID")+":   %s\n"+
			colorField("Kernel UUID")+":        %s\n"+
			colorField("Boot Session UUID")+":  %s\n"+
			colorField("iBoot Version")+":      %s\n"+
			colorField("Secure Boot")+":        %t\n"+
			colorField("Roots Installed")+":    %t\n"+
			colorField("Paniclog Version")+":   %s\n"+
			colorField("Kernel Slide")+":       %#x\n"+
			colorField("Kernel Text Base")+":   %#x\n"+
			colorField("Mach Absolute Time")+": %#x\n"+
			"\n%s\n"+
			"%s\n"+
			"%s\n"+
			"%s\n"+
			colorField("Compressor Info: ")+"%s\n"+
			"%s\n"+
			"%s",
		panic,
		p.DebuggerMessage,
		p.MemoryID,
		p.OsReleaseType,
		p.OsVersion,
		p.KernelVersion,
		p.KernelCacheUUID,
		p.KernelUUID,
		p.BootSessionUUID,
		p.IBootVersion,
		p.SecureBoot,
		p.RootsInstalled,
		p.PaniclogVersion,
		p.KernelSlide,
		p.KernelTextBase,
		p.MachAbsoluteTime,
		p.EpochTime,
		p.ZoneInfo,
		p.TPIDRx_ELy,
		cores,
		p.CompressorInfo,
		p.PanickedTask,
		p.PanickedThread)

}
