package tbd

const tbdTemplate = `--- !tapi-tbd
tbd-version:          4
targets:              [ {{ StringsJoin .Targets ", " }} ]
install-name:         '{{.Path}}'
{{ if .ReExports }}reexported-libraries:
  - targets:          [ {{ StringsJoin .Targets ", " }} ]
    libraries:        [ '{{ StringsJoin .ReExports "', '" }}' ]
{{ end -}}
exports:
  - targets:          [ {{ StringsJoin .Targets ", " }} ]
    symbols:          [ {{ StringsJoin .Symbols ",\n                       " }} ]
{{- if .ObjcClasses }}    
    objc-classes:    [ {{ StringsJoin .ObjcClasses ",\n                       " }} ]
{{- end }}
{{- if .ObjcIvars }}    
    objc-ivars:      [ {{ StringsJoin .ObjcIvars ",\n                       " }} ]
{{- end }}
`
