package crashlog

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"regexp"
	"strconv"
	"strings"

	"github.com/blacktop/ipsw/internal/utils"
)

// CrashLog is a crashlog object
type CrashLog struct {
	ReportVersion int
	HardwareModel string
	OSVersion     string
	OSBuild       string
	Process       string
	PID           int

	ExceptionType      string
	ExceptionSubtype   []string
	TerminationSignal  string
	TerminationReason  string
	TerminatingProcess string

	Images  []image
	Threads []thread

	CrashedThread int

	lines  []string
	closer io.Closer
}

type image struct {
	Name  string
	Start uint64
	End   uint64
	Slide uint64
	Arch  string
	UUID  string
	Path  string
}

type state map[string]uint64

// TODO: check that crashlog is arm64
func (s state) String() string {
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
		s["x0"], s["x1"], s["x2"], s["x3"],
		s["x4"], s["x5"], s["x6"], s["x7"],
		s["x8"], s["x9"], s["x10"], s["x11"],
		s["x12"], s["x13"], s["x14"], s["x15"],
		s["16"], s["x17"], s["x18"], s["x19"],
		s["x20"], s["x21"], s["x22"], s["x23"],
		s["x24"], s["x25"], s["x26"], s["x27"],
		s["x28"], s["fp"], s["lr"],
		s["sp"], s["pc"], s["cpsr"],
		s["esr"])
}

type thread struct {
	Number    int
	Name      string
	BackTrace []backtrace
	State     state

	lines []string
}

type backtrace struct {
	FrameNum int
	Image    *image
	Address  uint64
	LibAddr  uint64
	Offset   int
	Symbol   string
}

// Open opens the named file using os.Open and prepares it for use as a crashlog
func Open(name string) (*CrashLog, error) {

	crash := CrashLog{}

	f, err := os.Open(name)
	if err != nil {
		return nil, err
	}

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		crash.lines = append(crash.lines, scanner.Text())
	}
	if err := scanner.Err(); err != nil {
		fmt.Fprintln(os.Stderr, "reading standard input:", err)
	}

	if err := crash.getReportVersion(); err != nil {
		return nil, fmt.Errorf("failed to parse report version: %v", err)
	}
	if err := crash.getHardwareModel(); err != nil {
		return nil, fmt.Errorf("failed to parse hardware model: %v", err)
	}
	if err := crash.getOSVersion(); err != nil {
		return nil, fmt.Errorf("failed to parse os version: %v", err)
	}
	if err := crash.getProcess(); err != nil {
		return nil, fmt.Errorf("failed to parse process: %v", err)
	}
	if crash.ReportVersion != 104 && crash.ReportVersion != 105 {
		return nil, fmt.Errorf("unsupported crash log report version: %d", crash.ReportVersion)
	}

	if err := crash.getExceptionType(); err != nil {
		return nil, fmt.Errorf("failed to parse exception type: %v", err)
	}
	if err := crash.getExceptionSubtype(); err != nil {
		return nil, fmt.Errorf("failed to parse exception subtype: %v", err)
	}
	if err := crash.getTerminationSignal(); err != nil {
		return nil, fmt.Errorf("failed to parse termination signal: %v", err)
	}
	if err := crash.getTerminationReason(); err != nil {
		return nil, fmt.Errorf("failed to parse termination reason: %v", err)
	}
	if err := crash.getTerminatingProcess(); err != nil {
		return nil, fmt.Errorf("failed to parse terminating process: %v", err)
	}
	if err := crash.getTriggeringThread(); err != nil {
		return nil, fmt.Errorf("failed to parse triggering thread: %v", err)
	}

	if err := crash.getImages(); err != nil {
		return nil, fmt.Errorf("failed to parse images: %v", err)
	}
	if err := crash.getThreads(); err != nil {
		return nil, fmt.Errorf("failed to parse threads: %v", err)
	}
	if err := crash.getBackTraces(); err != nil {
		return nil, fmt.Errorf("failed to parse back traces: %v", err)
	}

	// TODO: prune unused images?

	crash.closer = f

	return &crash, nil
}

// Close closes the File.
func (c *CrashLog) Close() error {
	var err error

	if c.closer != nil {
		err = c.closer.Close()
		c.closer = nil
	}

	return err
}

func (c *CrashLog) String() string {
	return fmt.Sprintf(
		"Process:             %s [%d]\n"+
			"Hardware Model:      %s\n"+
			"OS Version:          %s\n"+
			"BuildID:             %s\n\n"+
			"Exception Type:      %s\n"+
			"Exception Subtype:\n%s\n\n"+
			"Termination Signal:  %s\n"+
			"Termination Reason:  %s\n"+
			"Terminating Process: %s\n"+
			"Triggered by Thread: %d\n",
		c.Process, c.PID,
		c.HardwareModel,
		c.OSVersion, c.OSBuild,
		c.ExceptionType,
		strings.Join(c.ExceptionSubtype, "\n"),
		c.TerminationSignal,
		c.TerminationReason,
		c.TerminatingProcess,
		c.CrashedThread,
	)
}

// getReportVersion fills out the report version
func (c *CrashLog) getReportVersion() error {
	re := regexp.MustCompile(`(\d+)`)

	for _, line := range c.lines {
		if strings.HasPrefix(line, "Report Version:") {
			version := re.FindString(line)
			i, err := strconv.Atoi(version)
			if err != nil {
				return err
			}
			c.ReportVersion = i
		}
	}

	return nil
}

// getHardwareModel parses hardware model in the crashlog
func (c *CrashLog) getHardwareModel() error {
	re := regexp.MustCompile(`Hardware Model:\s+(?P<model>\S+)`)

	for _, line := range c.lines {
		if re.MatchString(line) {
			matches := re.FindStringSubmatch(line)
			c.HardwareModel = matches[re.SubexpIndex("model")]
			return nil
		}
	}

	return nil
}

// getOSVersion parses OS version and build ID in the crashlog
func (c *CrashLog) getOSVersion() error {
	re := regexp.MustCompile(`^OS Version:\s+.+\s(?P<version>[0-9.]+)\s+\((?P<build>(\w+))\)$`)
	for _, line := range c.lines {
		if re.MatchString(line) {
			matches := re.FindStringSubmatch(line)
			c.OSVersion = matches[re.SubexpIndex("version")]
			c.OSBuild = matches[re.SubexpIndex("build")]
			return nil
		}
	}

	return nil
}

// getProcess parses the crashing process in the crashlog
func (c *CrashLog) getProcess() error {
	re := regexp.MustCompile(`^Process:\s+(?P<proc>\S+)\s\[(?P<pid>\d+)\]$`)
	for _, line := range c.lines {
		if re.MatchString(line) {
			matches := re.FindStringSubmatch(line)
			c.Process = matches[re.SubexpIndex("proc")]
			pid, err := strconv.Atoi(matches[re.SubexpIndex("pid")])
			if err != nil {
				return err
			}
			c.PID = pid
			return nil
		}
	}

	return nil
}

// getExceptionType parses exception type in the crashlog
func (c *CrashLog) getExceptionType() error {
	re := regexp.MustCompile(`^Exception Type:\s+(?P<type>.+)$`)

	for _, line := range c.lines {
		if re.MatchString(line) {
			matches := re.FindStringSubmatch(line)
			c.ExceptionType = matches[re.SubexpIndex("type")]
			return nil
		}
	}

	return nil
}

// getExceptionSubtype parses exception subtype in the crashlog
func (c *CrashLog) getExceptionSubtype() error {
	re := regexp.MustCompile(`Exception Subtype:\s+(?P<stype>.+)`)

	found := false
	for _, line := range c.lines {
		if strings.HasPrefix(line, "Exception Subtype:") {
			found = true
		}
		if found {
			if len(line) == 0 {
				return nil
			}
			if re.MatchString(line) {
				matches := re.FindStringSubmatch(line)
				c.ExceptionSubtype = append(c.ExceptionSubtype, matches[re.SubexpIndex("stype")])
			} else {
				c.ExceptionSubtype = append(c.ExceptionSubtype, line)
			}
		}
	}

	return nil
}

// getTerminationSignal parses termination signal in the crashlog
func (c *CrashLog) getTerminationSignal() error {
	re := regexp.MustCompile(`^Termination Signal:\s+(?P<signal>.+)$`)

	for _, line := range c.lines {
		if re.MatchString(line) {
			matches := re.FindStringSubmatch(line)
			c.TerminationSignal = matches[re.SubexpIndex("signal")]
			return nil
		}
	}

	return nil
}

// getHardwareModel parses termination reason in the crashlog
func (c *CrashLog) getTerminationReason() error {
	re := regexp.MustCompile(`^Termination Reason:\s+(?P<reason>.+)$`)

	for _, line := range c.lines {
		if re.MatchString(line) {
			matches := re.FindStringSubmatch(line)
			c.TerminationReason = matches[re.SubexpIndex("reason")]
			return nil
		}
	}

	return nil
}

// getTerminatingProcess parses terminating process in the crashlog
func (c *CrashLog) getTerminatingProcess() error {
	re := regexp.MustCompile(`^Terminating Process:\s+(?P<proc>.+)$`)

	for _, line := range c.lines {
		if re.MatchString(line) {
			matches := re.FindStringSubmatch(line)
			c.TerminatingProcess = matches[re.SubexpIndex("proc")]
			return nil
		}
	}

	return nil
}

// getTriggeringThread parses triggering thread in the crashlog
func (c *CrashLog) getTriggeringThread() error {
	re := regexp.MustCompile(`Triggered by Thread:\s+(?P<thread>\d+)`)

	for _, line := range c.lines {
		if re.MatchString(line) {
			matches := re.FindStringSubmatch(line)
			thread, err := strconv.Atoi(matches[re.SubexpIndex("thread")])
			if err != nil {
				return err
			}
			c.CrashedThread = thread
			return nil
		}
	}

	return nil
}

// getImages parses all the binary images in the crashlog
func (c *CrashLog) getImages() error {
	re := regexp.MustCompile(`(?:\s+)(?P<start>\w+)\s-\s+(?P<end>\w+)\s+(?P<name>.+)\s+(?P<arch>rmv[4-8][tfsk]?|arm64\S*|i386|x86_64\S)\s+\<?(?P<uuid>[[:xdigit:]]{32})?\>?\s* (?P<path>\/.*)\s*$`)
	found := false
	for _, line := range c.lines {
		if strings.HasPrefix(line, "Binary Images") {
			found = true
			continue
		}
		if found {
			if len(line) == 0 || strings.EqualFold(line, "EOF") {
				return nil
			}
			if re.MatchString(line) {
				matches := re.FindStringSubmatch(line)
				start, err := utils.ConvertStrToInt(matches[re.SubexpIndex("start")])
				if err != nil {
					return err
				}
				end, err := utils.ConvertStrToInt(matches[re.SubexpIndex("end")])
				if err != nil {
					return err
				}
				c.Images = append(c.Images, image{
					Name:  matches[re.SubexpIndex("name")],
					Start: start,
					End:   end,
					Arch:  matches[re.SubexpIndex("arch")],
					UUID:  matches[re.SubexpIndex("uuid")],
					Path:  matches[re.SubexpIndex("path")],
				})
			}
		}
	}

	return nil
}

// getThreads parses all the threads in the crashlog
func (c *CrashLog) getThreads() error {
	var t thread

	re := regexp.MustCompile(`Thread\s+(?P<num>\d+)\s?(Highlighted|Crashed)?(name:\s+(?P<name>.*))?`)
	stateRE := regexp.MustCompile(`\s+(?P<reg>\w+): (?P<addr>0x\w+)`)

	found := false
	isThreadState := false

	for _, line := range c.lines {
		if strings.HasPrefix(line, "Thread ") && !strings.Contains(line, "Thread State") {
			found = true
		} else if strings.Contains(line, "Thread State") {
			isThreadState = true
			c.Threads[c.CrashedThread].State = make(map[string]uint64)
		}

		if found {
			if len(line) == 0 {
				c.Threads = append(c.Threads, t)
				t = thread{}
				found = false
				continue
			}
			if re.MatchString(line) {
				matches := re.FindStringSubmatch(line)
				num, err := strconv.Atoi(matches[re.SubexpIndex("num")])
				if err != nil {
					return err
				}
				t.Number = num
				if re.SubexpIndex("name") >= 0 {
					if len(matches[re.SubexpIndex("name")]) > 0 {
						t.Name = matches[re.SubexpIndex("name")]
					}
				}
			} else {
				t.lines = append(t.lines, line)
			}
		}

		if isThreadState {
			if len(line) == 0 {
				isThreadState = false
				continue
			}
			if stateRE.MatchString(line) {
				matches := stateRE.FindAllStringSubmatch(line, -1)
				for _, match := range matches {
					reg := match[stateRE.SubexpIndex("reg")]
					addr, err := utils.ConvertStrToInt(match[stateRE.SubexpIndex("addr")])
					if err != nil {
						return err
					}
					c.Threads[c.CrashedThread].State[reg] = addr
				}
			}
		}

	}

	return nil
}

// getBackTraces parses all thread backtraces in the crashlog
func (c *CrashLog) getBackTraces() error {

	re := regexp.MustCompile(`^(?P<num>\d+)\s+(?P<image>\S.*?)\s+(?P<addr>0x\w+)\s+(?P<libaddr>0x\w+)\s+\+\s+(?P<off>\d+)?.*$`)

	for idx, thread := range c.Threads {
		for _, btline := range thread.lines {
			if re.MatchString(btline) {
				var imgIdx int
				matches := re.FindStringSubmatch(btline)
				imageName := matches[re.SubexpIndex("image")]
				for iidx, img := range c.Images {
					if img.Name == imageName {
						imgIdx = iidx
					}
				}
				num, err := strconv.Atoi(matches[re.SubexpIndex("num")])
				if err != nil {
					return err
				}
				addr, err := utils.ConvertStrToInt(matches[re.SubexpIndex("addr")])
				if err != nil {
					return err
				}
				libAddr, err := utils.ConvertStrToInt(matches[re.SubexpIndex("libaddr")])
				if err != nil {
					return err
				}
				off, err := strconv.Atoi(matches[re.SubexpIndex("off")])
				if err != nil {
					return err
				}
				c.Threads[idx].BackTrace = append(c.Threads[idx].BackTrace, backtrace{
					FrameNum: num,
					Address:  addr,
					LibAddr:  libAddr,
					Offset:   off,
					Image:    &c.Images[imgIdx],
				})
			}
		}
	}

	return nil
}
