# go-lzfse
Go bindings for lzfse compression

# lzss

[![GoDoc](https://godoc.org/github.com/blacktop/lzss?status.svg)](https://godoc.org/github.com/blacktop/lzss) [![License](http://img.shields.io/:license-mit-blue.svg)](http://doge.mit-license.org)

> Go bindings for [lzfse](https://github.com/lzfse/lzfse) compression.

---

## Requirements

### `macOS`

```bash
$ brew install lzfse
```

## Install

```bash
go get github.com/blacktop/go-lzfse
```

## Examples

```golang
import (
    "io/ioutil"
    "unsafe"
    "log"

    lzfse "github.com/blacktop/go-lzfse"
    "github.com/pkg/errors"
)

func main() {
    dat, err := ioutil.ReadFile("kernelcache.release.iphone12.decompressed")
    if err != nil {
        log.Fatal(errors.Wrap(err, "failed to read compressed file"))
    }

    var decompressed bytes.Buffer

    scratch := make([]byte, lzfse.DecodeScratchSize())
    p := unsafe.Pointer(&scratch[0])

    lzfse.DecodeBuffer(decompressed.Bytes(), uint(len(decompressed)), string(dat), uint(len(dat)), p)

    err = ioutil.WriteFile("kernelcache.release.iphone12.decompressed", decompressed, 0644)
    if err != nil {
        log.Fatal(errors.Wrap(err, "failed to decompress file"))
    }
}
```

## Credit

- <https://github.com/zchee/go-lzfse>

## License

MIT Copyright (c) 2019 blacktop
