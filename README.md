# get-ipsws [WIP] :construction:

[![Circle CI](https://circleci.com/gh/blacktop/get-ipsws.png?style=shield)](https://circleci.com/gh/blacktop/get-ipsws) [![Github All Releases](https://img.shields.io/github/downloads/blacktop/get-ipsws/total.svg)](https://github.com/blacktop/get-ipsws) [![GitHub release](https://img.shields.io/github/release/blacktop/get-ipsws.svg)](https://github.com/https://github.com/blacktop/get-ipsws/releases/releases) [![License](http://img.shields.io/:license-mit-blue.svg)](http://doge.mit-license.org)

> Download ipsw(s) from theiphonewiki.com

---

## Getting Started

```bash
$ get-ipsws --help

Usage: get-ipsws [OPTIONS] COMMAND [arg...]
IPSW Downloader
Version: , BuildTime:
Author: blacktop - <https://github.com/blacktop>

Options:
  --verbose, -V                    verbose output
  --device value, -d value         iOS Device [$IOS_DEVICE]
  --ios-version value, --iv value  iOS Version [$IOS_VERSION]
  --build value, -b value          iOS Build [$IOS_BUILD]
  --keys value, -k value           iOS Keys [$IOS_KEYS]
  --help, -h                       show help
  --version, -v                    print the version

Commands:
  generate  crawl theiphonewiki.com and create JSON database
  help      Shows a list of commands or help for one command

Run 'get-ipsws COMMAND --help' for more information on a command.
```

### Download an `ipsw`

```bash
$ get-ipsws --keys iPhone10,1 --build 16A5364a
```

## TODO

- [ ] use https://github.com/gocolly/colly
- [ ] create offline copy of ipsw.me API
- [ ] crawl ipsw.me for non-betas

## Issues

Find a bug? Want more features? Find something missing in the documentation? Let me know! Please don't hesitate to [file an issue](https://github.com/blacktop/get-ipsws/issues/new)

## License

MIT Copyright (c) 2018 **blacktop**
