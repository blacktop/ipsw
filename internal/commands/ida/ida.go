package ida

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/apex/log"
	"github.com/blacktop/ipsw/internal/commands/docker"
	"github.com/blacktop/ipsw/internal/utils"
	"github.com/google/uuid"
)

const (
	DarwinPathGlob      = "/Applications/IDA\\ Pro\\ */ida64.app/Contents/MacOS"
	LinuxPath           = ""
	WindowsPath         = ""
	IDAProCompleteImage = "Apple DYLD cache for %s (complete image)"
	IDAPro8SingleModule = "Apple DYLD cache for %s (single module)"
	IDPro9SingleModule  = "Apple DYLD cache for %s (select module(s))"
)

type Config struct {
	IdaPath    string
	InputFile  string
	Frameworks []string

	AutoAnalyze  bool
	AutoAccept   bool
	BatchMode    bool
	LoadAddress  string
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
	ScriptFile   string
	ScriptArgs   []string
	FileType     string
	ExtraArgs    []string
	Verbose      bool
	RunInDocker  bool
	DockerImage  string
	DockerEntry  string
}

type Client struct {
	ctx  context.Context
	conf *Config
	cmd  *exec.Cmd
}

func NewClient(ctx context.Context, conf *Config) (*Client, error) {
	cli := &Client{ctx: ctx, conf: conf}

	executable := filepath.Join(conf.IdaPath, "idat64")
	if _, err := os.Stat(executable); os.IsNotExist(err) {
		executable = filepath.Join(conf.IdaPath, "idat")
	}
	if conf.EnableGUI {
		executable = filepath.Join(conf.IdaPath, "ida64")
		if _, err := os.Stat(executable); os.IsNotExist(err) {
			executable = filepath.Join(conf.IdaPath, "ida")
		}
	}
	if _, err := os.Stat(executable); os.IsNotExist(err) {
		return nil, fmt.Errorf("IDA Pro binary not found: %s", executable)
	}

	if conf.RunInDocker {
		conf.EnableGUI = false
	}

	// IDA Help: Command line switches - https://www.hex-rays.com/products/ida/support/idadoc/417.shtml
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
	if conf.LoadAddress != "" {
		args = append(args, fmt.Sprintf("-b%s", conf.LoadAddress)) // load address (hex)
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
		/*
			The -O command line switch allows the user to pass options to the plugins. A plugin which
			uses options should call the get_plugin_options() function to get them.
			Since there may be many plugins written by independent programmers, each options will have
			a prefix -O in front of the plugin name.

			For example, a plugin named "decomp" should expect its parameters to be in the following format:
			        -Odecomp:option1:option2:option3
			In this case, get_plugin_options("decomp") will return the "option1:option2:option3" part of the options string.
			If there are several -O options in the command line, they will be concatenated with ':' between them.
		*/
		for _, opt := range conf.Options {
			args = append(args, fmt.Sprintf("-O%s", opt))
		}
	}
	if conf.ScriptFile != "" {
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
		if len(conf.ScriptArgs) > 0 {
			args = append(args, fmt.Sprintf("-S%s %s", conf.ScriptFile, strings.Join(conf.ScriptArgs, " ")))
		} else {
			args = append(args, fmt.Sprintf("-S%s", conf.ScriptFile))
		}
	}
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
	if conf.Verbose {
		cli.cmd.Stdout = os.Stdout
		cli.cmd.Stderr = os.Stderr
	}

	utils.Indent(log.Debug, 2)(cli.cmd.String())

	return cli, nil
}

func (c *Client) Run() error {
	if c.conf.RunInDocker {
		cli := docker.NewClient(
			uuid.New().String(),          // ID
			c.conf.DockerImage,           // Image
			[]string{c.conf.DockerEntry}, // Entrypoint
			c.cmd.Args[1:],               // Args
			c.conf.Env,                   // Env
			[]docker.HostMounts{ // Mounts
				{
					Source:   filepath.Dir(c.conf.Output),
					Target:   filepath.Dir(c.conf.Output),
					ReadOnly: false,
				},
				{
					Source:   filepath.Dir(c.conf.InputFile),
					Target:   filepath.Dir(c.conf.InputFile),
					ReadOnly: false,
				}})
		return cli.Run(c.ctx)
	}
	return c.cmd.Run()
}

func (c *Client) Stop() error {
	return c.cmd.Process.Signal(syscall.SIGTERM)
}
