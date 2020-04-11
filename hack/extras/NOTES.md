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
