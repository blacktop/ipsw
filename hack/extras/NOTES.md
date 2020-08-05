# NOTES

## Misc

To get `github.com/mattn/go-sqlite3` golang dep

```bash
$ export CGO_ENABLED=1; export CC=gcc; go get -v -x github.com/mattn/go-sqlite3
```

To demangle swift symbols

```bash
$ echo "__TFCSo8NSStringCfMS_FT6stringSS_S_" | xcrun swift-demangle

___C.NSString.__allocating_init(__C.NSString.Type) -> (string: Swift.String) -> __C.NSString
```

### lzfse

#### src

- https://github.com/lzfse/lzfse

Ideas

- https://github.com/minio/c2goasm
- https://github.com/minio/asm2plan9s

### firmware

- https://gist.github.com/mrmacete/42fc2371c3d8761ad7e8b607750ed153
- https://github.com/mrmacete/sepsplit

### JS/Web

- https://github.com/indutny/macho

### Disass

- https://github.com/decomp/decomp
- https://blog.gopheracademy.com/advent-2018/llvm-ir-and-go/
- https://blog.felixangell.com/an-introduction-to-llvm-in-go
- https://ldhldh.myds.me:10081/docs/llvm342_docs/_mach_o_dump_8cpp.html

### DWARF

- https://github.com/volatilityfoundation/dwarf2json/blob/master/main.go
- https://github.com/dutchcoders/disassembler/blob/master/disassembler.go
