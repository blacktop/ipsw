---
description: How to build ipsw from source.
---

# Building

## Requirements {#requirements}

- [Golang](https://go.dev/dl/) *1.19+*

## Install the Go binary

Get *golang*

```bash
brew install go
```

Build the `ipsw` binary

```bash
git clone https://github.com/blacktop/ipsw.git
cd ipsw
make build
```

## Build for all supported platforms using [goreleaser](https://goreleaser.com) and [zig](https://ziglang.org)

Get *goreleaser* and *zig*

```bash
brew install goreleaser zig
```

Build for all supported platforms

```bash
git clone https://github.com/blacktop/ipsw.git
cd ipsw
make snapshot
```

:::info offline

### To dev and build *WITHOUT* internet

On internet connected machine with Go installed download all Golang lib dependencies

```bash
git clone https://github.com/blacktop/ipsw.git
cd ipsw
go mod vendor # this downloads all of the dependencies into the `vendor` folder
```

Now copy the project's directory to _no-net_ machine

Add `--mod=vendor` to use the Go deps in the vendor folder

```bash
CGO_ENABLED=1 go build --mod=vendor ./cmd/ipsw
```

:::