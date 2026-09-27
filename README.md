<p align="center">
  <a href="https://github.com/blacktop/ipsw"><img alt="IPSW Logo" src="https://github.com/blacktop/ipsw/raw/master/www/static/img/logo/ipsw.svg" height="140" /></a>
  <h1 align="center">ipsw</h1>
  <h4><p align="center">iOS/macOS Research Swiss Army Knife</p></h4>
  <p align="center">
    <a href="https://github.com/blacktop/ipsw/actions" alt="Actions">
          <img src="https://github.com/blacktop/ipsw/actions/workflows/go.yml/badge.svg" /></a>
    <a href="https://github.com/blacktop/ipsw/releases/latest" alt="Downloads">
          <img src="https://img.shields.io/github/downloads/blacktop/ipsw/total.svg" /></a>
    <a href="https://github.com/blacktop/ipsw/releases" alt="GitHub Release">
          <img src="https://img.shields.io/github/release/blacktop/ipsw.svg" /></a>
    <a href="http://doge.mit-license.org" alt="LICENSE">
          <img src="https://img.shields.io/:license-mit-blue.svg" /></a>
</p>
<br>

**ipsw** is a command-line toolkit for Apple firmware research and reverse engineering. Download and unpack IPSWs and OTAs, inspect Mach-O binaries and dyld shared caches, analyze kernelcaches, and work with connected iOS devices.

[Agent skill](https://github.com/blacktop/ipsw-skill) · [Install](#install) · [CLI examples](#cli-examples) · [Documentation](https://blacktop.github.io/ipsw)

## Use ipsw with an AI agent

Start with **[ipsw-skill](https://github.com/blacktop/ipsw-skill)** if you're working in Claude Code, Codex, Gemini CLI, or another agent that supports skills. It gives the agent command references and workflows for firmware extraction, binary analysis, and Apple platform research.

[Install the ipsw CLI](#install), then add the skill:

```sh
npx skills add https://github.com/blacktop/ipsw-skill --skill ipsw
```

You can then ask for a task in plain language. For example:

> Download the latest IPSW for iPhone 15 Pro and extract its kernelcache.

> Dump the Objective-C headers for SpringBoardServices from this dyld shared cache.

> Compare the KEXTs in these two kernelcaches.

The [skill README](https://github.com/blacktop/ipsw-skill#installation) has setup instructions for individual agents, including the Claude Code plugin and Gemini CLI extension.

## Install

### macOS

The maintainer's Homebrew tap includes the extras build:

```sh
brew install blacktop/tap/ipsw
```

The Homebrew core formula is also available: `brew install ipsw`.

### Linux

```sh
sudo snap install ipsw
```

### Windows

```powershell
scoop bucket add blacktop https://github.com/blacktop/scoop-bucket.git
scoop install blacktop/ipsw
```

You can also download binaries from [GitHub Releases](https://github.com/blacktop/ipsw/releases/latest). See the [installation guide](https://blacktop.github.io/ipsw/docs/getting-started/installation) for other packages and optional dependencies. Some commands depend on the host OS or build variant; Frida support, for example, has a separate build.

## What you can do

| Area | Tools |
| --- | --- |
| Firmware | Download IPSWs, OTAs, macOS installers, Xcode, and KDKs; extract components and compare builds |
| Mach-O | Inspect load commands, symbols, signatures, and entitlements; disassemble ARM64 code |
| dyld shared caches | Find symbols and cross-references, extract dylibs, dump Objective-C headers, and inspect Swift metadata |
| Kernel | Extract KEXTs, inspect syscalls and symbols, and compare kernelcaches |
| Firmware components | Parse IMG4, decrypt AEA archives, and inspect iBoot and coprocessor firmware |
| Devices | List devices and apps, transfer files with AFC, capture logs, and mount developer images |
| App Store Connect | Manage certificates, bundle IDs, devices, and provisioning profiles |
| Research | Symbolicate crash logs, debug over SSH, trace with Frida, and decompile with an LLM |

## CLI examples

Replace the example file paths with your own. Run `ipsw --help` or add `--help` to any subcommand for its options.

### Download and extract firmware

```sh
# Download the latest IPSW for iPhone 15 Pro
ipsw download ipsw --device iPhone16,1 --latest

# Inspect a local IPSW and extract its kernelcache
ipsw info /path/to/firmware.ipsw
ipsw extract --kernel /path/to/firmware.ipsw

# Compare two firmware builds
ipsw diff /path/to/old.ipsw /path/to/new.ipsw
```

### Explore a dyld shared cache

```sh
ipsw dyld info /path/to/dyld_shared_cache_arm64e

# Extract Foundation for use in other tools
ipsw dyld extract /path/to/dyld_shared_cache_arm64e Foundation

# Dump headers directly from the cache
ipsw class-dump /path/to/dyld_shared_cache_arm64e SpringBoardServices --headers -o headers
```

Use the cache directly for Objective-C analysis: extracted dylibs can still reference metadata stored elsewhere in the cache.

### Inspect binaries and kernelcaches

```sh
# Select an architecture explicitly for universal binaries
ipsw macho info /path/to/binary --arch arm64e
ipsw macho disass /path/to/binary --arch arm64e --symbol _main

# Search a directory of binaries for an imported symbol
ipsw macho search /path/to/binaries --import 'CCCrypt'

# List KEXTs, then extract one by its full bundle ID
ipsw kernel kexts /path/to/kernelcache
ipsw kernel extract /path/to/kernelcache com.apple.driver.ASIOKit -o kexts
```

### Work with a connected device

```sh
ipsw idev list
ipsw idev apps ls
ipsw idev afc ls /
ipsw idev syslog
```

### Decompile with an LLM

The `macho disass` and `dyld disass` commands can send disassembly to a configured LLM provider with `--dec`. See the [decompiler guide](https://blacktop.github.io/ipsw/docs/guides/decompiler) for provider setup, model selection, and examples.

## Configuration and automation

The CLI reads YAML configuration from `~/.config/ipsw/config.yaml`; use `--config` to select another file. See [config.example.yml](config.example.yml) and the [configuration guide](https://blacktop.github.io/ipsw/docs/getting-started/configuration) for settings and environment variables.

For scripts, select an architecture with `--arch` when opening universal binaries and use a full dylib path when a short name is ambiguous. Commands that support `--json` document it in their help.

The separate `ipswd` daemon exposes a REST API for automation. See the [API reference](https://blacktop.github.io/ipsw/api/).

## Documentation and community

- [Agent skill and setup](https://github.com/blacktop/ipsw-skill)
- [Guides and command reference](https://blacktop.github.io/ipsw)
- [Precomputed firmware diffs](https://github.com/blacktop/ipsw-diffs)
- [GitHub Discussions](https://github.com/blacktop/ipsw/discussions)
- [Issue tracker](https://github.com/blacktop/ipsw/issues)
- [DeepWiki](https://deepwiki.com/blacktop/ipsw), an AI-generated guide to the codebase

When reporting a bug, include `ipsw version`, the command you ran, and the relevant firmware build or file type. Redact personal information from logs and crash reports.

## Build and contribute

Building from source requires Go 1.26 or later and a C toolchain for CGO:

```sh
git clone https://github.com/blacktop/ipsw.git
cd ipsw
make build
```

See [CONTRIBUTING.md](CONTRIBUTING.md) for development and contribution guidelines.

## Credits

Thanks to Jonathan Levin for his tools and iOS internals documentation, the Apple security research community, and everyone who contributes code, bug reports, and research.

## License

[MIT](LICENSE).
