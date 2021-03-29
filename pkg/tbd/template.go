package tbd

const tbdTemplate = `--- !tapi-tbd-v3
archs:           [ {{ StringsJoin .Archs ", " }} ]
platform:        {{.Platform}}
install-name:    {{.Path}}
current-version: {{.Version}}
objc-constraint: none
exports:
  - archs:           [ {{ StringsJoin .Archs ", " }} ]
    symbols:         [ {{ StringsJoin .Symbols ",\n                       " }} ]
...
`
