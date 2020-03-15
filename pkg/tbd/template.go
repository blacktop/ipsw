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

// const tbdTemplate = `---
// archs:           [ {{ StringsJoin .Archs ", " }} ]
// uuids:           [ {{ .Archs }}: {{ .UUID }} ]
// platform:        {{.Platform}}
// install-name:    {{.Path}}
// current-version: {{.Version}}
// exports:
//   - archs:           [ {{ StringsJoin .Archs ", " }} ]
//     symbols:         [ {{ StringsJoin .Symbols ", " }} ]
//   objc-classes:    [  {{ StringsJoin .ObjcSyms ", " }}   end ]
// ...
// `
