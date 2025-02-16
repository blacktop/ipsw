package crashlog

import (
	"bufio"
	"fmt"
	"regexp"
	"strings"

	"github.com/apex/log"
	"github.com/spf13/cast"
)

type Field struct {
	Title string
	Value any
}

func pad(in string, ammount int) string {
	if ammount >= len(in) {
		return in + strings.Repeat(" ", ammount-len(in))
	}
	return in
}

func (f *Field) String() string {
	if f == nil {
		return ""
	}
	switch v := f.Value.(type) {
	case string:
		return fmt.Sprintf("%s %s\n", pad(colorField(f.Title)+":", 36), v)
	case uint64:
		return fmt.Sprintf("%s %#x\n", pad(colorField(f.Title)+":", 36), v)
	case bool:
		return fmt.Sprintf("%s %t\n", pad(colorField(f.Title)+":", 36), v)
	default:
		return fmt.Sprintf("%s %v\n", pad(colorField(f.Title)+":", 36), f.Value)
	}
}

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
	found    bool
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
	if !z.found {
		return ""
	}
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
			colorImage("  Extra   ")+": %s\n\n",
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
	if len(t) == 0 {
		return ""
	}
	var tpidrx string
	for key, val := range t {
		tpidrx += fmt.Sprintf(colorImage("    %-3s", key)+": %#016x\n", val)
	}
	return fmt.Sprintf(colorField("TPIDRx_ELy")+"\n%s\n", tpidrx)
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
	return fmt.Sprintf("%s:   %#016x, %d %s, %d %s, %s %d: %s", colorField("Panicked Task"), p.Address, p.Pages, colorField("pages"), p.Threads, colorField("threads"), colorField("pid"), p.PID, colorImage(p.Name))
}

type State struct {
	LR uint64
	FP uint64
}

func (s State) String() string {
	return fmt.Sprintf(colorImage("lr")+": %#016x - "+colorImage("fp")+": %#016x", s.LR, s.FP)
}

type BackTraceKext struct {
	Name    string
	Version string
	UUID    string
	Range   Range
}

type PanickedThread struct {
	TID       int
	Backtrace uint64
	Address   uint64
	CallStack []State
	Kexts     []BackTraceKext
}

func (p PanickedThread) String() string {
	callstack := "\n"
	for _, state := range p.CallStack {
		callstack += fmt.Sprintf("    %s\n", state)
	}
	kexts := ""
	if len(p.Kexts) > 0 {
		kexts = colorField("Kernel Extensions In Backtrace") + ":\n"
	}
	for _, kext := range p.Kexts {
		kexts += fmt.Sprintf("    %s (%v) %s @ %s\n", kext.Name, kext.Version, kext.UUID, kext.Range)
	}
	return fmt.Sprintf(colorField("Panicked Thread")+": %#016x, "+colorField("backtrace")+": %#016x, "+colorField("tid")+": %d%s%s", p.Address, p.Backtrace, p.TID, callstack, kexts)
}

type LastStartedKext struct {
	StartedAt uint64
	Name      string
	Version   string
	Address   uint64
	Size      uint64
}

func (l *LastStartedKext) String() string {
	if l == nil {
		return ""
	}
	return fmt.Sprintf(
		colorField("Last Started Kext at")+": %#x: %s %s (%s %#x, %s %d)\n",
		l.StartedAt,
		colorImage(l.Name),
		l.Version,
		colorField("addr"),
		l.Address,
		colorField("size"),
		l.Size)
}

type LoadedKexts []LoadedKext

func (l LoadedKexts) String() string {
	if len(l) == 0 {
		return ""
	}
	loadedKexts := ""
	for _, kext := range l {
		loadedKexts += fmt.Sprintf("    %s\n", kext)
	}
	return fmt.Sprintf(colorField("Loaded Kexts:")+"\n%s\n", loadedKexts)
}

type LoadedKext struct {
	Name    string
	Version string
}

func (l LoadedKext) String() string {
	return fmt.Sprintf("%s %s", colorImage(l.Name), l.Version)
}

type Panic210 struct {
	Panic                          string
	DebuggerMessage                *Field // string
	MemoryID                       *Field // uint64
	OsReleaseType                  *Field // string
	OsVersion                      *Field // string
	KernelVersion                  *Field // string
	FilesetKernelCacheUUID         *Field // string
	KernelCacheUUID                *Field // string
	KernelUUID                     *Field // string
	BootSessionUUID                *Field // string
	IBootVersion                   *Field // string
	SecureBoot                     *Field // bool
	RootsInstalled                 *Field // bool
	PaniclogVersion                *Field // string
	KernelCacheSlide               *Field // uint64
	KernelCacheBase                *Field // uint64
	KernelSlide                    *Field // uint64
	KernelTextBase                 *Field // uint64
	KernelTextExecSlide            *Field // uint64
	KernelTextExecBase             *Field // uint64
	SptmLoadAddress                *Field // uint64
	SptmUUID                       *Field // string
	TxmLoadAddress                 *Field // uint64
	TxmUUID                        *Field // string
	DebugHdrAddress                *Field // uint64
	DebugHdrEntryCount             *Field // uint64
	DebugHdrKernelCacheLoadAddress *Field // uint64
	DebugHdrKernelCacheUUID        *Field // string
	MachAbsoluteTime               *Field // uint64

	EpochTime EpochTime

	ZoneInfo ZoneInfo

	TPIDRx_ELy TPIDRx_ELy

	Cores []Core

	CompressorInfo *Field // string
	PanickedTask   PanickedTask
	PanickedThread PanickedThread

	LastStartedKext *LastStartedKext
	LoadedKexts     LoadedKexts

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

	crash.Panic = crash.getPanicString()

	crash.DebuggerMessage, err = crash.getStrField("Debugger Message", "Debugger message: ")
	if err != nil {
		log.WithError(err).Error("failed to get debugger message")
	}
	crash.MemoryID, err = crash.getIntField("Memory ID", "Memory ID:")
	if err != nil {
		log.WithError(err).Error("failed to get memory ID")
	}
	crash.OsReleaseType, err = crash.getStrField("OS Release Type", "OS release type: ")
	if err != nil {
		log.WithError(err).Error("failed to get OS release type")
	}
	crash.OsVersion, err = crash.getStrField("OS Version", "OS version: ")
	if err != nil {
		log.WithError(err).Error("failed to get OS version")
	}
	crash.KernelVersion, err = crash.getStrField("Kernel Version", "Kernel version: ")
	if err != nil {
		log.WithError(err).Error("failed to get kernel version")
	}
	crash.KernelCacheUUID, err = crash.getStrField("KernelCache UUID", "KernelCache UUID: ")
	if err != nil {
		log.WithError(err).Debug("failed to get kernelcache UUID")
	}
	crash.FilesetKernelCacheUUID, err = crash.getStrField("Fileset KernelCache UUID", "Fileset KernelCache UUID: ")
	if err != nil {
		log.WithError(err).Debug("failed to get fileset kernelcache UUID")
	}
	crash.KernelUUID, err = crash.getStrField("Kernel UUID", "Kernel UUID: ")
	if err != nil {
		log.WithError(err).Debug("failed to get kernel UUID")
	}
	crash.BootSessionUUID, err = crash.getStrField("Boot Session UUID", "Boot session UUID: ")
	if err != nil {
		log.WithError(err).Debug("failed to get boot session UUID")
	}
	crash.IBootVersion, err = crash.getStrField("iBoot Version", "iBoot version: ")
	if err != nil {
		log.WithError(err).Error("failed to get iBoot version")
	}
	crash.SecureBoot, err = crash.getBoolField("Secure Boot", "secure boot?: ")
	if err != nil {
		log.WithError(err).Debug("failed to get secure boot")
	}
	crash.RootsInstalled, err = crash.getBoolField("Roots Installed", "roots installed: ")
	if err != nil {
		log.WithError(err).Debug("failed to get roots installed")
	}
	crash.PaniclogVersion, err = crash.getStrField("Paniclog Version", "Paniclog version: ")
	if err != nil {
		log.WithError(err).Error("failed to get paniclog version")
	}
	crash.KernelCacheSlide, err = crash.getIntField("KernelCache Slide", "KernelCache slide:")
	if err != nil {
		log.WithError(err).Debug("failed to get kernelcache slide")
	}
	crash.KernelCacheBase, err = crash.getIntField("KernelCache Base", "KernelCache base:")
	if err != nil {
		log.WithError(err).Debug("failed to get kernelcache base")
	}
	crash.KernelSlide, err = crash.getIntField("Kernel Slide", "Kernel slide:")
	if err != nil {
		log.WithError(err).Error("failed to get kernel slide")
	}
	crash.KernelTextBase, err = crash.getIntField("Kernel Text Base", "Kernel text base:")
	if err != nil {
		log.WithError(err).Error("failed to get kernel text base")
	}
	crash.KernelTextExecSlide, err = crash.getIntField("Kernel Text Exec Slide", "Kernel text exec slide:")
	if err != nil {
		log.WithError(err).Debug("failed to get kernel text exec slide")
	}
	crash.KernelTextExecBase, err = crash.getIntField("Kernel Text Exec Base", "Kernel text exec base:")
	if err != nil {
		log.WithError(err).Debug("failed to get kernel text exec base")
	}
	crash.SptmLoadAddress, err = crash.getIntField("SPTM Load Address", "SPTM load address:")
	if err != nil {
		log.WithError(err).Debug("failed to get SPTM load address")
	}
	crash.SptmUUID, err = crash.getStrField("SPTM UUID", "SPTM UUID: ")
	if err != nil {
		log.WithError(err).Debug("failed to get SPTM UUID")
	}
	crash.TxmLoadAddress, err = crash.getIntField("TXM Load Address", "TXM load address:")
	if err != nil {
		log.WithError(err).Debug("failed to get TXM load address")
	}
	crash.TxmUUID, err = crash.getStrField("TXM UUID", "TXM UUID: ")
	if err != nil {
		log.WithError(err).Debug("failed to get TXM UUID")
	}
	crash.DebugHdrAddress, err = crash.getIntField("Debug Header Address", "Debug Header address:")
	if err != nil {
		log.WithError(err).Debug("failed to get Debug Header address")
	}
	crash.DebugHdrEntryCount, err = crash.getStrField("Debug Header Entry Count", "Debug Header entry count:")
	if err != nil {
		log.WithError(err).Debug("failed to get Debug Header entry count")
	}
	crash.DebugHdrKernelCacheLoadAddress, err = crash.getIntField("Debug Header KernelCache Load Address", "Debug Header kernelcache load address:")
	if err != nil {
		log.WithError(err).Debug("failed to get TXM load address")
	}
	crash.DebugHdrKernelCacheUUID, err = crash.getStrField("Debug Header KernelCache UUID", "Debug Header kernelcache UUID: ")
	if err != nil {
		log.WithError(err).Debug("failed to get TXM UUID")
	}
	crash.MachAbsoluteTime, err = crash.getIntField("Mach Absolute Time", "mach_absolute_time:")
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
		log.WithError(err).Debug("failed to get TPIDRx_ELy")
	}
	if err := crash.getCores(); err != nil {
		log.WithError(err).Error("failed to get cores")
	}
	crash.CompressorInfo, err = crash.getStrField("Compressor Info", "Compressor Info: ")
	if err != nil {
		log.WithError(err).Debug("failed to get compressor info")
	}
	if err := crash.getPanickedTask(); err != nil {
		log.WithError(err).Error("failed to get panicked task")
	}
	if err := crash.getPanickedThread(); err != nil {
		log.WithError(err).Error("failed to get panicked thread")
	}
	if err := crash.getLastStartedKext(); err != nil {
		log.WithError(err).Debug(err.Error())
	}
	if err := crash.getLoadedKexts(); err != nil {
		log.WithError(err).Debug(err.Error())
	}

	return crash, nil
}

func (p *Panic210) getBoolField(title, key string) (*Field, error) {
	for _, line := range p.lines {
		if strings.HasPrefix(line, key) {
			switch strings.ToLower(strings.TrimPrefix(line, key)) {
			case "yes", "1", "true":
				return &Field{Title: title, Value: true}, nil
			case "no", "0", "false":
				return &Field{Title: title, Value: false}, nil
			default:
				return nil, fmt.Errorf("failed to parse bool: %s", line)
			}
		}
	}
	return nil, fmt.Errorf("failed to find '%s'", key)
}
func (p *Panic210) getStrField(title, key string) (*Field, error) {
	for _, line := range p.lines {
		if strings.HasPrefix(line, key) {
			return &Field{Title: title, Value: strings.TrimPrefix(line, key)}, nil
		}
	}
	return nil, fmt.Errorf("failed to find '%s'", key)
}
func (p *Panic210) getIntField(title, key string) (*Field, error) {
	for _, line := range p.lines {
		if strings.HasPrefix(line, key) {
			return &Field{Title: title, Value: cast.ToUint64(strings.TrimSpace(strings.TrimPrefix(line, key)))}, nil
		}
	}
	return nil, fmt.Errorf("failed to find '%s'", key)
}
func (p *Panic210) getPanicString() string {
	var lines []string
	for _, line := range p.lines {
		if strings.HasPrefix(line, "Debugger message:") {
			break
		}
		lines = append(lines, line)
	}
	return strings.Join(lines, "\n")
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
			p.ZoneInfo.found = true
			continue
		}
		if p.ZoneInfo.found {
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

	if !p.ZoneInfo.found {
		return fmt.Errorf("failed to find Zone info")
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
	kextsFound := false
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
			kextInBtRE := regexp.MustCompile(`^\s+Kernel Extensions in backtrace:`)
			if kextInBtRE.MatchString(line) {
				kextsFound = true
				continue
			}
			if kextsFound {
				kextRE := regexp.MustCompile(`^\s+(?P<name>\w+)\((?P<version>[0-9.]+)\) \[(?P<uuid>.*)\]@(?P<start>\w+)->(?P<end>\w+)`)
				matches := kextRE.FindStringSubmatch(line)
				if len(matches) < 6 {
					continue
				}
				p.PanickedThread.Kexts = append(p.PanickedThread.Kexts, BackTraceKext{
					Name:    matches[1],
					Version: matches[2],
					UUID:    matches[3],
					Range:   Range{Start: cast.ToUint64(matches[4]), End: cast.ToUint64(matches[5])},
				})
			}
		}
	}
	if found {
		return nil
	}
	return fmt.Errorf("failed to find panicked thread")
}
func (p *Panic210) getLastStartedKext() (err error) {
	re := regexp.MustCompile(`^last started kext at`)
	found := false
	for _, line := range p.lines {
		if re.MatchString(line) {
			ptRE := regexp.MustCompile(`^last started kext at (?P<start>.+): (?P<name>.*)\s+(?P<version>[0-9.]+) \(addr (?P<addr>\w+), size (?P<size>\w+)\)`)
			matches := ptRE.FindStringSubmatch(line)
			if len(matches) < 4 {
				continue
			}
			p.LastStartedKext = &LastStartedKext{
				StartedAt: cast.ToUint64(matches[1]),
				Name:      matches[2],
				Version:   matches[3],
				Address:   cast.ToUint64(matches[4]),
				Size:      cast.ToUint64(matches[5]),
			}
			found = true
			continue
		}
	}
	if found {
		return nil
	}
	return fmt.Errorf("failed to find 'last started kext at'")
}
func (p *Panic210) getLoadedKexts() (err error) {
	re := regexp.MustCompile(`^loaded kexts:`)
	found := false
	for _, line := range p.lines {
		if re.MatchString(line) {
			found = true
			continue
		}
		if found {
			lkRE := regexp.MustCompile(`^(?P<name>\S+)\s+(?P<version>[0-9.]+)`)
			matches := lkRE.FindStringSubmatch(line)
			if len(matches) < 3 {
				break
			}
			p.LoadedKexts = append(p.LoadedKexts, LoadedKext{
				Name:    matches[1],
				Version: matches[2],
			})
		}
	}
	if found {
		return nil
	}
	return fmt.Errorf("failed to find 'loaded kexts:'")
}
func (p *Panic210) String() string {
	panic := p.Panic
	start, rest, ok := strings.Cut(p.Panic, ":")
	if ok {
		panic = colorField("Panic") + fmt.Sprintf("\n%s\n  %s", start, rest)
	}
	var cores string
	for _, core := range p.Cores {
		cores += fmt.Sprintf("%s\n", core)
	}
	return fmt.Sprintf(
		"%s\n\n"+ // panic
			"%s"+
			"%s"+
			"%s"+
			"%s"+
			"%s"+
			"%s"+
			"%s"+
			"%s"+
			"%s"+
			"%s"+
			"%s"+
			"%s"+
			"%s"+
			"%s"+
			"%s"+
			"%s"+
			"%s"+
			"%s"+
			"%s"+
			"%s"+
			"%s"+
			"%s"+
			"%s"+
			"%s"+
			"%s"+
			"%s"+
			"%s"+
			"\n%s\n"+ // EpochTime
			"%s"+ // ZoneInfo
			"%s"+ // TPIDRx_ELy
			"%s\n"+ // cores
			"%s"+ // CompressorInfo
			"%s\n"+ // PanickedTask
			"%s"+ // PanickedThread
			"%s"+ // LastStartedKext
			"%s", // LoadedKexts
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
		p.KernelCacheSlide,
		p.KernelCacheBase,
		p.KernelSlide,
		p.KernelTextBase,
		p.KernelTextExecSlide,
		p.KernelTextExecBase,
		p.SptmLoadAddress,
		p.SptmUUID,
		p.TxmLoadAddress,
		p.TxmUUID,
		p.DebugHdrAddress,
		p.DebugHdrEntryCount,
		p.DebugHdrKernelCacheLoadAddress,
		p.DebugHdrKernelCacheUUID,
		p.MachAbsoluteTime,
		p.EpochTime,
		p.ZoneInfo,
		p.TPIDRx_ELy,
		cores,
		p.CompressorInfo,
		p.PanickedTask,
		p.PanickedThread,
		p.LastStartedKext,
		p.LoadedKexts,
	)

}
