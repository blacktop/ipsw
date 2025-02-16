package dscu

import (
	"bytes"
	"compress/gzip"
	_ "embed"
	"fmt"
	"text/template"
)

//go:embed data/objc.gz
var objcScriptData []byte

//go:embed data/swift.gz
var swiftScriptData []byte

const idaDscuPyScriptTemplate = `
# https://hex-rays.com/products/ida/news/7_2/the_mac_rundown/

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

IDA_VERSION = ida_kernwin.get_kernel_version().split('.')

# load some commonly used system dylibs
{{- range $framework := .Frameworks }}
print("[ipsw] loading {{ $framework }}")
dscu_load_module("{{ $framework }}")
{{- end }}

print("[ipsw] analyzing objc types")
load_and_run_plugin("objc", 1)
print("[ipsw] analyzing NSConcreteGlobalBlock objects")
load_and_run_plugin("objc", 4)

# prevent IDA from creating functions with the noreturn attribute.
# in dyldcache modules it is common that IDA will think a function doesn't return,
# but in reality it just branches to an address outside of the current module.
# this can break the analysis at times.
if IDA_VERSION[0] == 8 and IDA_VERSION[1] <= 2:
	idaapi.cvar.inf.af &= ~AF_ANORET # This errors with: 'NoneType' object has no attribute 'af' on IDA Pro 9.x

print("[ipsw] perform auto-analysis...")
auto_mark_range(0, BADADDR, AU_FINAL);
auto_wait()

print("[ipsw] analyzing NSConcreteStackBlock objects")
load_and_run_plugin("objc", 5)
{{ if .CloseIDA }}
# close IDA and save the database
qexit(0)
{{- end }}

if IDA_VERSION[0] == 8 and IDA_VERSION[1] <= 2:
	print("[ipsw] running objc_stubs.py ...")
	fix_objc_stubs()
	print("[ipsw] running fix outlined functions")
	fix_outlined_functions()
else:
	print("[ipsw] skipping objc fixups ...")	


print("[ipsw] running swift fixups")
#fix_proto_conf_desc()
#fix_assocty()
swift()

print("[ipsw] applying objc hotkeys...")
set_hotkeys()
`

// GenerateScript generates a IDAPython script from a template
func GenerateScript(frameworks []string, closeIDA bool) (string, error) {
	var tplOut bytes.Buffer

	tmpl := template.Must(template.New("ida").Parse(idaDscuPyScriptTemplate))

	if err := tmpl.Execute(&tplOut, struct {
		Frameworks []string
		CloseIDA   bool
	}{
		Frameworks: frameworks,
		CloseIDA:   closeIDA,
	}); err != nil {
		return "", fmt.Errorf("failed to generate IDAPython script: %v", err)
	}

	return tplOut.String(), nil
}

// ExpandScript expands the embedded gzipped IDAPython script
func ExpandScript() (string, error) {
	zr, err := gzip.NewReader(bytes.NewReader(objcScriptData))
	if err != nil {
		return "", fmt.Errorf("failed to create gzip reader: %v", err)
	}

	var buf bytes.Buffer
	if _, err := buf.ReadFrom(zr); err != nil {
		return "", fmt.Errorf("failed to read from gzip reader: %v", err)
	}
	zr.Close()

	zr, err = gzip.NewReader(bytes.NewReader(swiftScriptData))
	if err != nil {
		return "", fmt.Errorf("failed to create gzip reader: %v", err)
	}
	if _, err := buf.ReadFrom(zr); err != nil {
		return "", fmt.Errorf("failed to read from gzip reader: %v", err)
	}
	zr.Close()

	return buf.String(), nil
}
