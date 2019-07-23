# ranger - io.ReaderAt with range requests! [![coverage report](https://gitlab.howett.net/DHowett/ranger/badges/master/coverage.svg)](https://gitlab.howett.net/DHowett/ranger/commits/master)

## INSTALL
```
$ go get howett.net/ranger
```

## OVERVIEW
Package ranger provides an implementation of io.ReaderAt and io.ReadSeeker which makes
partial document requests. Ranger ships with a range fetcher that operates on an HTTP resource
using the Range: header.

## USE

```go
package main

import (
	"archive/zip"
	"io"
	"howett.net/ranger"
	"net/url"
	"os"
)

func main() {
	url, _ := url.Parse("http://example.com/example.zip")

	reader, _ := ranger.NewReader(&ranger.HTTPRanger{URL: url})
	length, _ := reader.Length()
	zipreader, _ := zip.NewReader(reader, length)

	data := make([]byte, zipreader.File[0].UncompressedSize64)
	rc, _ := zipreader.File[0].Open()
	io.ReadFull(rc, data)
	rc.Close()
}
```
