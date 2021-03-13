package tbd

const tbdTemplate = `---
archs:           [ {{ StringsJoin .Archs ", " }} ]
platform:        {{.Platform}}
install-name:    {{.Path}}
current-version: {{.Version}}
exports:
  - archs:           [ {{ StringsJoin .Archs ", " }} ]
    symbols:         [ {{ StringsJoin .Symbols ", " }} ]
...
`
