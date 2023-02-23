package ida

import (
	"bytes"
	"context"
	"fmt"
	"html/template"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/AlecAivazis/survey/v2"
	"github.com/AlecAivazis/survey/v2/terminal"
	"github.com/apex/log"
	"github.com/blacktop/ipsw/internal/utils"
	"github.com/pkg/errors"
)

const (
	darwinPath  = "/Applications/IDA\\ Pro\\ */ida64.app/Contents/MacOS"
	linuxPath   = ""
	windowsPath = ""
)

const idaDscuPyScriptTemplate = `
def dscu_load_module(module):
	node = idaapi.netnode()
	node.create("$ dscu")
	node.supset(2, module)
	load_and_run_plugin("dscu", 1)

def dscu_load_region(ea):
	node = idaapi.netnode()
	node.create("$ dscu")
	node.altset(3, ea)
	load_and_run_plugin("dscu", 2)

# load some commonly used system dylibs
{{- range $framework := .Frameworks }}
print("Loading {{ $framework }}")
dscu_load_module("{{ $framework }}")
{{- end }}

print("analyzing objc types")
load_and_run_plugin("objc", 1)
print("analyzing NSConcreteGlobalBlock objects")
load_and_run_plugin("objc", 4)

# prevent IDA from creating functions with the noreturn attribute.
# in dyldcache modules it is common that IDA will think a function doesn't return,
# but in reality it just branches to an address outside of the current module.
# this can break the analysis at times.
idaapi.cvar.inf.af &= ~AF_ANORET

print("perform autoanalysis...")
auto_mark_range(0, BADADDR, AU_FINAL);
auto_wait()

print("analyzing NSConcreteStackBlock objects")
load_and_run_plugin("objc", 5)

# close IDA and save the database
qexit(0)
`

type Config struct {
	IdaPath    string
	InputFile  string
	Frameworks []string

	AutoAnalyze  bool
	AutoAccept   bool
	BatchMode    bool
	LogFile      string
	Output       string
	Env          []string
	EntryPoint   string
	EnableGUI    bool
	TempDatabase bool
	CompressDB   bool
	DeleteDB     bool
	Compiler     string
	Processor    string
	Options      []string
	ScriptArgs   []string
	PluginArgs   []string
	FileType     string
	ExtraArgs    []string
}

type Client struct {
	conf *Config
	cmd  *exec.Cmd
}

func NewClient(ctx context.Context, conf *Config) (*Client, error) {
	var path string

	cli := &Client{conf: conf}

	if conf.IdaPath == "" {
		switch runtime.GOOS {
		case "darwin":
			matches, err := filepath.Glob(darwinPath)
			if err != nil {
				return nil, err
			}
			if len(matches) == 0 {
				return nil, fmt.Errorf("IDA Pro not found")
			}
			if len(matches) == 1 {
				path = matches[0]
			} else { // len(matches) > 1
				prompt := &survey.Select{
					Message: "Multiple IDA Pro versions found:",
					Options: matches,
				}
				if err := survey.AskOne(prompt, &path); err != nil {
					if err == terminal.InterruptErr {
						log.Warn("Exiting...")
						os.Exit(0)
					}
					return nil, err
				}
			}
		case "linux":
			// path = linuxPath
			return nil, fmt.Errorf("supply IDA Pro '--ida-path' for linux (e.g. /opt/ida-7.0/)")
		case "windows":
			// path = windowsPath
			return nil, fmt.Errorf("supply IDA Pro '--ida-path' for windows (e.g. C:\\Program Files\\IDA 7.0)")
		default:
			return nil, fmt.Errorf("unsupported OS: %s", runtime.GOOS)
		}
	} else {
		path = conf.IdaPath
	}

	executable := filepath.Join(path, "idat64")
	if conf.EnableGUI {
		executable = filepath.Join(path, "ida64")
	}

	args := []string{}
	if conf.AutoAnalyze {
		args = append(args, "-a-")
	} else {
		args = append(args, "-a") // disable auto analysis. (-a- enables it)
	}
	if !conf.EnableGUI || conf.AutoAccept {
		args = append(args, "-A") // autonomous mode. IDA will not display dialog boxes.
		// Designed to be used together with -S switch.
	}
	if conf.BatchMode {
		args = append(args, "-B") // batch mode. IDA will generate .IDB and .ASM files automatically
	}
	if conf.CompressDB {
		args = append(args, "-P+") // compress database (create zipped idb)
	} else {
		args = append(args, "-P") // pack database (create unzipped idb)
	}
	if conf.LogFile != "" {
		args = append(args, fmt.Sprintf("-L%s", conf.LogFile)) // name of the log file
	}
	if conf.DeleteDB {
		args = append(args, "-c") // disassemble a new file (delete the old database)
	}
	if conf.Compiler != "" {
		args = append(args, fmt.Sprintf("-C'%s'", conf.Compiler)) // set compiler in format name:abi
	}
	if conf.Processor != "" {
		args = append(args, fmt.Sprintf("-p'%s'", conf.Processor)) // processor type
	}
	if conf.EntryPoint != "" {
		args = append(args, fmt.Sprintf("-i%s", conf.EntryPoint)) // program entry point (hex)
	}
	if conf.TempDatabase {
		args = append(args, "-DABANDON_DATABASE=YES")
	}
	if len(conf.Options) > 0 {
		for _, opt := range conf.Options {
			args = append(args, fmt.Sprintf("-O%s", opt))
		}
	}
	if len(conf.ScriptArgs) > 0 {
		// TODO: add script args
	}
	if len(conf.PluginArgs) > 0 {
		// TODO: add plugin args (same thing as options)
	}
	// Script
	script, err := cli.GenerateDSCUScript()
	if err != nil {
		return nil, err
	}
	tmp, err := os.CreateTemp("", "*.py")
	if err != nil {
		return nil, err
	}
	if _, err := tmp.WriteString(script); err != nil {
		return nil, err
	}
	if err := tmp.Close(); err != nil {
		return nil, err
	}
	/*
		Execute a script file when the database is opened.
		The script file extension is used to determine which extlang
		will run the script.
		It is possible to pass command line arguments after the script name.
		For example: -S"myscript.idc argument1 \"argument 2\" argument3"
		The passed parameters are stored in the "ARGV" global IDC variable.
		Use "ARGV.count" to determine the number of arguments.
		The first argument "ARGV[0]" contains the script name.
	*/
	args = append(args, fmt.Sprintf("-S%s", tmp.Name()))

	if conf.FileType != "" {
		/*
			Interpret the input file as the specified file type
			The file type is specified as a prefix of a file type
			visible in the 'load file' dialog box
			To specify archive member put it after the colon char,
			for example: -TZIP:classes.dex
			You can specify any nested paths:
			-T<ftype>[:<member>{:<ftype>:<member>}[:<ftype>]]
			IDA does not display the 'load file' dialog in this case
		*/
		args = append(args, fmt.Sprintf("-T%s", conf.FileType))
	}
	if conf.Output != "" {
		args = append(args, fmt.Sprintf("-o%s", conf.Output)) // specify the output database (implies -c)
	}
	args = append(args, conf.ExtraArgs...)

	args = append(args, conf.InputFile)

	cli.cmd = exec.CommandContext(ctx, executable, args...)
	cli.cmd.Env = append(os.Environ(), conf.Env...)
	cli.cmd.Stdout = os.Stdout
	cli.cmd.Stderr = os.Stderr

	utils.Indent(log.Debug, 2)(cli.cmd.String())

	return cli, nil
}

// Generate generates a IDAPython script from a template
func (c *Client) GenerateDSCUScript() (string, error) {
	var tplOut bytes.Buffer

	tmpl := template.Must(template.New("ida").Funcs(template.FuncMap{"StringsJoin": strings.Join}).Parse(idaDscuPyScriptTemplate))

	if err := tmpl.Execute(&tplOut, c.conf); err != nil {
		return "", errors.Wrap(err, "failed to execute template")
	}

	return tplOut.String(), nil
}

func (c *Client) Run() error {
	return c.cmd.Run()
}
