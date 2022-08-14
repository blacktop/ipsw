package debugserver

const (
	PyPath     = "/tmp/iosretools_lldb.py"
	ScriptPath = "/tmp/iosretools_lldb.sh"
	LLDBShell  = "/usr/bin/lldb"
	LLDBScript = `
platform select remote-ios
target create "{{.AppPath}}"
script device_app="{{.Container}}"
script connect_url="connect://127.0.0.1:{{.Port}}"
script output_path=""
script error_path=""
command script import "{{.PyPath}}"
command script add -f {{.PyName}}.connect_command connect
command script add -s asynchronous -f {{.PyName}}.run_command run
command script add -s asynchronous -f {{.PyName}}.autoexit_command autoexit
command script add -s asynchronous -f {{.PyName}}.safequit_command safequit
connect
run
`
	StopAtEntry = "launchInfo.SetLaunchFlags(lldb.eLaunchFlagStopAtEntry)"
	PyScript    = `import time
import os
import sys
import shlex
import lldb

listener = None
startup_error = lldb.SBError()
	`
)
