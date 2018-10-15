# partialzip

[![GoDoc](https://godoc.org/github.com/blacktop/partialzip?status.svg)](https://godoc.org/github.com/blacktop/partialzip) [![License](http://img.shields.io/:license-mit-blue.svg)](http://doge.mit-license.org)

> Partial Implementation of PartialZip in Go

---

## Install

```bash
go get github.com/blacktop/partialzip
```

## Examples

```golang
import (
    "fmt"

    "github.com/blacktop/partialzip"
)

func main() {
    pzip, err := partialzip.New("https://apple.com/ipsw/download/link")
    if err != nil {
        log.Fatal(err)
    }
    fmt.Println(pzip.List())

    n, err := pzip.Get("kernelcache.release.iphone11")
    if err != nil {
        log.Fatal(err)
    }
    fmt.Printf("extracting %s, wrote %d bytes\n", "kernelcache.release.iphone11", n)

    n, err = pzip.Get("BuildManifest.plist")
    if err != nil {
        log.Fatal(err)
    }
    fmt.Printf("extracting %s, wrote %d bytes\n", "BuildManifest.plist", n)
}
```

```bash
extracting "kernelcache.release.iphone11", wrote 17842148 bytes
extracting "BuildManifest.plist", wrote 206068 bytes
```

## Credits

- [planetbeing/partial-zip](https://github.com/planetbeing/partial-zip) _(written in C)_
- [marcograss/partialzip](https://github.com/marcograss/partialzip) _(written in Rust)_

## License

MIT Copyright (c) 2018 blacktop
