package tbd

const tbdTemplate = `--- !tapi-tbd
tbd-version:     4
targets:         {{.Targets}}
install-name:    '{{.Path}}'
exports:
  - targets:         {{.Targets}}
    symbols:         [ {{ StringsJoin .Symbols ",\n                       " }} ]
{{- if .ObjcClasses }}    
    objc-classes:    [ {{ StringsJoin .ObjcClasses ",\n                       " }} ]
{{- end }}
{{- if .ObjcIvars }}    
    objc-ivars:      [ {{ StringsJoin .ObjcIvars ",\n                       " }} ]
{{- end }}
...

`
