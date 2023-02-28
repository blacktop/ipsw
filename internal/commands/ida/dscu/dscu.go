package dscu

import (
	"bytes"
	"fmt"
	"text/template"
)

const idaDscuPyScriptTemplate = ` # https://hex-rays.com/products/ida/news/7_2/the_mac_rundown/

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
idaapi.cvar.inf.af &= ~AF_ANORET

print("[ipsw] perform auto-analysis...")
auto_mark_range(0, BADADDR, AU_FINAL);
auto_wait()

print("[ipsw] analyzing NSConcreteStackBlock objects")
load_and_run_plugin("objc", 5)
{{ if .CloseIDA }}
# close IDA and save the database
qexit(0)
{{- end }}
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
