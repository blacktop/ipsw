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

## What is `ipsw` 🤔

**ipsw** is a comprehensive command-line research framework for iOS and macOS. It provides an extensive toolkit for security researchers, reverse engineers, jailbreak developers, and iOS enthusiasts to download, parse, and analyze Apple firmware and interact with iOS devices.

### Core Capabilities

- 📱 **IPSW/OTA Analysis** - Download, extract, and analyze iOS firmware files
- 🔍 **Binary Analysis** - Advanced Mach-O parsing with ARM disassembly and AI assistance  
- 🧠 **dyld_shared_cache** - Complete shared cache analysis with ObjC/Swift class dumping
- 🔧 **Kernel Analysis** - Kernelcache parsing, syscall extraction, and symbolication
- 📲 **Device Interaction** - Comprehensive iOS device management and debugging
- 🔐 **Firmware Research** - IMG4, iBoot, SEP, and co-processor firmware analysis
- 🏪 **App Store Connect** - Full API integration for app and certificate management
- 🛠️ **Developer Tools** - SSH, Frida, debugging, and reverse engineering utilities

## Quick Start

### Installation

#### macOS
Using blacktop tap (includes extras)
```bash
brew install blacktop/tap/ipsw
```
Using official Homebrew formula
```bash
brew install ipsw
```

#### Linux
```bash
sudo snap install ipsw
```

#### Windows
```bash
scoop bucket add blacktop https://github.com/blacktop/scoop-bucket.git 
scoop install blacktop/ipsw
```

#### Go Install
```bash
go install github.com/blacktop/ipsw/cmd/ipsw@latest
```

### Basic Usage

```bash
# Download latest iOS IPSW
ipsw download ipsw --device iPhone16,1 --latest

# Extract kernelcache
ipsw extract --kernel iPhone16,1_18.2_22C150_Restore.ipsw

# Analyze dyld_shared_cache
ipsw dyld info /path/to/dyld_shared_cache_arm64

# Get device information
ipsw idev list
```

## Major Features

### 📱 IPSW & OTA Management
- **Download Sources**: Apple, AppleDB, Developer Portal, RSS feeds, GitHub, iTunes, Wikipedia
- **File Types**: IPSW, OTA, macOS installers, Xcode, KDKs, PCC files
- **Operations**: Extract, diff, mount, analyze metadata

```bash
ipsw download ipsw --device iPhone16,1 --latest
ipsw extract --kernel iPhone16,1_18.2_22C150_Restore.ipsw
ipsw diff iPhone16,1_18.1_22B83_Restore.ipsw iPhone16,1_18.2_22C150_Restore.ipsw
```

### 🔍 Binary Analysis & Reverse Engineering
- **Mach-O Parsing**: Complete binary analysis with symbol extraction
- **ARM Disassembly**: ARM v9-a disassembler with AI-powered analysis
- **Code Signing**: Verify signatures, analyze entitlements
- **Binary Patching**: Add, modify, or remove patches

```bash
ipsw macho info /path/to/binary
ipsw macho disass /path/to/binary --symbol _main
ipsw macho search /path/to/binary --string "password"
```

### 🧠 dyld_shared_cache Analysis
- **Cache Parsing**: Extract and analyze the complete shared cache structure
- **ObjC Analysis**: Class dumps, method analysis, protocol parsing
- **Swift Support**: Swift class dumping and analysis (experimental)
- **Symbol Management**: Symbol extraction and address resolution

```bash
ipsw dyld info /path/to/dyld_shared_cache
ipsw dyld extract /path/to/dyld_shared_cache --dylib Foundation
ipsw dyld objc class /path/to/dyld_shared_cache --class NSString
```

### 📲 iOS Device Interaction (`idev`)
- **File System**: Browse and transfer files via AFC
- **App Management**: Install, uninstall, and analyze applications
- **Backup & Restore**: Complete device backup operations
- **Development**: Mount developer images, capture logs, packet capture
- **Diagnostics**: Battery info, crash logs, system diagnostics

```bash
ipsw idev list
ipsw idev afc ls /
ipsw idev apps ls
ipsw idev backup create
ipsw idev syslog
```

### 🔐 Firmware & Security Analysis
- **IMG4**: Parse and decrypt Image4 format files
- **iBoot**: Bootloader analysis and research
- **SEP**: Secure Enclave Processor firmware analysis
- **AEA**: Apple Encrypted Archives decryption
- **Co-processors**: AOP, DCP, GPU, Camera firmware analysis

```bash
ipsw img4 dec iBoot.img4
ipsw fw sep iPhone16,1_18.2_22C150_Restore.ipsw
ipsw fw iboot iPhone16,1_18.2_22C150_Restore.ipsw
```

### 🏪 App Store Connect Integration
- **Certificate Management**: iOS/macOS certificates and profiles
- **Device Registration**: Manage development devices
- **App Management**: Bundle IDs, capabilities, and reviews
- **Provisioning**: Complete provisioning profile lifecycle

```bash
ipsw appstore cert ls
ipsw appstore device reg --name "My Device" --udid 1234567890
ipsw appstore profile create --name "Development Profile"
```

### 🛠️ Advanced Research Tools
- **Symbolication**: Crash log analysis and symbol resolution
- **Class Dumping**: ObjC and Swift class extraction
- **SSH Access**: Jailbroken device SSH with debugserver
- **Frida Integration**: Dynamic instrumentation capabilities
- **AI Powered Decompiler**: Integration with Claude, OpenAI, Gemini, Ollama and OpenRouter

```bash
ipsw symbolicate crash.ips --dsym /path/to/symbols
ipsw class-dump /path/to/binary
ipsw ssh debugserver
```

## Architecture

**ipsw** consists of two main components:

- **`ipsw`** - Main CLI tool with complete analysis capabilities
- **`ipswd`** - REST API daemon for remote operations and automation

## Configuration

ipsw supports YAML configuration files and environment variables:

```bash
# Create config directory
mkdir -p ~/.config/ipsw

# Copy example config
cp config.example.yml ~/.config/ipsw/config.yaml
```

### Database Support
- **SQLite** (default) - Local storage
- **PostgreSQL** - Production deployments

### AI Decompiler
> https://blacktop.github.io/ipsw/docs/guides/decompiler
```bash
❱ ipsw macho disass /System/Library/PrivateFrameworks/ApplePushService.framework/apsd --entry \
             --dec --dec-model "Claude 3.7 Sonnet"
   • Loading symbol cache file...
   • Decompiling... 🕒
```
```objc
int main(int argc, char *argv[]) {
    @autoreleasepool {
        __set_user_dir_suffix(@"com.apple.apsd");

        @autoreleasepool {
            APSDaemon *daemon = [[APSDaemon alloc] init];

            if (daemon) {
                NSRunLoop *runLoop = [NSRunLoop currentRunLoop];
                [runLoop run];
                [runLoop release];
            }

            [daemon release];
        }

        return 0;
    }

    @catch (NSException *exception) {
        if ([exception reason] == 1) {
            id exceptionObj = [exception retain];
            id logger = [APSLog daemon];

            if (_os_log_type_enabled(logger, 0x11)) {
                [exceptionObj logWithLogger:logger];
            }

            [logger release];
            [exceptionObj release];
        }
    }
}
```

## Use Cases

### Security Research
- Vulnerability analysis and exploit development
- Firmware security assessment
- Binary reverse engineering

### Jailbreak Development  
- Bootchain analysis and exploitation
- Kernel extension research
- System modification and patching

### iOS Development
- App debugging and analysis
- Certificate and provisioning management
- Device testing and automation

### Digital Forensics
- Device data extraction and analysis
- Timeline reconstruction
- Artifact analysis

## Requirements

- **Go**: 1.24+ (for building from source)
- **Platform**: macOS, Linux, Windows
- **USB**: libusb for device interaction
- **Optional**: AI API keys for enhanced analysis

## Documentation

- **Website**: [https://blacktop.github.io/ipsw](https://blacktop.github.io/ipsw)
- **API Docs**: REST API documentation available at `/docs` when running `ipswd`
- **Examples**: Comprehensive usage examples in the documentation

### 🆕 AI-Powered Wiki

Ask questions about the repository using AI:
- [DeepWiki for IPSW](https://deepwiki.com/blacktop/ipsw)

> [!WARNING]
> AI responses may contain hallucinations - verify important information.

## Community Resources

### 📊 IPSW Diffs
Pre-computed firmware differences: [ipsw-diffs](https://github.com/blacktop/ipsw-diffs)

### 💬 Community
[![Follow Twitter](https://img.shields.io/badge/follow_on_twitter-1DA1F2?style=for-the-badge&logo=twitter&logoColor=white)](https://twitter.com/blacktop__)
[![Follow Mastodon](https://img.shields.io/badge/follow_on_mastodon-6364FF?style=for-the-badge&logo=mastodon&logoColor=white)](https://mastodon.social/@blacktop)
[![GitHub Discussions](https://img.shields.io/badge/GITHUB_DISCUSSION-181717?style=for-the-badge&logo=github&logoColor=white)](https://github.com/blacktop/ipsw/discussions)

## Contributing

We welcome contributions! Please see [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

### Development
```bash
git clone https://github.com/blacktop/ipsw.git
cd ipsw
make build
```

## Known Issues

- **macOS IPSW Support**: Some macOS firmware operations may have compatibility issues
- **Testing**: Comprehensive testing is challenging due to the variety of firmware versions and device types
- **Resource Intensive**: Some operations require significant memory and processing power

> Create an [issue](https://github.com/blacktop/ipsw/issues) if you encounter problems - fixes are prioritized! A comprehensive test suite is planned for future releases.

## Credits

Huge thanks to:
- **Jonathan Levin** for his legendary tools and comprehensive iOS internals documentation
- **The iOS research community** for continuous innovation and knowledge sharing
- All contributors who help make this project better

## Stargazers

[![Stargazers over time](https://starchart.cc/blacktop/ipsw.svg?variant=adaptive)](https://starchart.cc/blacktop/ipsw)

## License

MIT Copyright (c) 2018-2025 **blacktop**