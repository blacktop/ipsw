module github.com/blacktop/ipsw

go 1.19

require (
	github.com/99designs/keyring v1.2.2
	github.com/AlecAivazis/survey/v2 v2.3.6
	github.com/PuerkitoBio/goquery v1.8.0
	github.com/alecthomas/chroma v0.10.0
	github.com/apex/log v1.9.0
	github.com/blacktop/arm64-cgo v1.0.55
	github.com/blacktop/go-dwarf v1.0.7
	github.com/blacktop/go-macho v1.1.125
	github.com/blacktop/go-plist v1.0.1
	github.com/blacktop/lzfse-cgo v1.1.19
	github.com/blacktop/lzss v0.1.1
	github.com/blacktop/ranger v1.0.3
	github.com/caarlos0/ctrlc v1.2.0
	github.com/dustin/go-humanize v1.0.0
	github.com/fatih/color v1.13.0
	github.com/frida/frida-go v0.5.2
	github.com/fullsailor/pkcs7 v0.0.0-20190404230743-d7302db945fa
	github.com/gen2brain/beeep v0.0.0-20220909211152-5a9ec94374f6
	github.com/gocolly/colly/v2 v2.1.0
	github.com/google/gousb v1.1.2
	github.com/hashicorp/go-version v1.6.0
	github.com/hinshun/vt10x v0.0.0-20220301184237-5011da428d02 // indirect
	github.com/jinzhu/gorm v1.9.16
	github.com/mattn/go-sqlite3 v2.0.3+incompatible // indirect
	github.com/mitchellh/go-homedir v1.1.0
	github.com/mitchellh/mapstructure v1.5.0
	github.com/olekukonko/tablewriter v0.0.5
	github.com/pkg/errors v0.9.1
	github.com/sergi/go-diff v1.2.0
	github.com/shurcooL/githubv4 v0.0.0-20221229060216-a8d4a561cc93
	github.com/spf13/cast v1.5.0
	github.com/spf13/cobra v1.6.1
	github.com/spf13/viper v1.14.0
	github.com/ulikunitz/xz v0.5.11
	github.com/unicorn-engine/unicorn v0.0.0-20221122205502-56f3bdedb42d
	github.com/vbauerster/mpb/v7 v7.5.3
	github.com/xi2/xz v0.0.0-20171230120015-48954b6210f8
	golang.org/x/crypto v0.5.0
	golang.org/x/net v0.5.0
	golang.org/x/oauth2 v0.4.0
	golang.org/x/sync v0.1.0
	golang.org/x/sys v0.4.0
	golang.org/x/term v0.4.0
	gopkg.in/yaml.v3 v3.0.1
)

// TODO: remove this once https://github.com/spf13/cast/pull/155 is merged
replace github.com/spf13/cast => github.com/blacktop/cast v1.5.1

// replace github.com/blacktop/go-macho => ../go-macho
// replace github.com/blacktop/arm64-cgo => ../arm64-cgo
// replace github.com/unicorn-engine/unicorn => ./unicorn2

require (
	github.com/99designs/go-keychain v0.0.0-20191008050251-8e49817e8af4 // indirect
	github.com/VividCortex/ewma v1.2.0 // indirect
	github.com/acarl005/stripansi v0.0.0-20180116102854-5a71ef0e047d // indirect
	github.com/andybalholm/cascadia v1.3.1 // indirect
	github.com/antchfx/htmlquery v1.2.5 // indirect
	github.com/antchfx/xmlquery v1.3.13 // indirect
	github.com/antchfx/xpath v1.2.1 // indirect
	github.com/cpuguy83/go-md2man/v2 v2.0.2 // indirect
	github.com/danieljoos/wincred v1.1.2 // indirect
	github.com/dlclark/regexp2 v1.7.0 // indirect
	github.com/dvsekhvalnov/jose2go v1.5.0 // indirect
	github.com/fsnotify/fsnotify v1.6.0 // indirect
	github.com/go-toast/toast v0.0.0-20190211030409-01e6764cf0a4 // indirect
	github.com/gobwas/glob v0.2.3 // indirect
	github.com/godbus/dbus v0.0.0-20190726142602-4481cbc300e2 // indirect
	github.com/godbus/dbus/v5 v5.1.0 // indirect
	github.com/golang/groupcache v0.0.0-20210331224755-41bb18bfe9da // indirect
	github.com/golang/protobuf v1.5.2 // indirect
	github.com/google/uuid v1.3.0 // indirect
	github.com/gsterjov/go-libsecret v0.0.0-20161001094733-a6f4afe4910c // indirect
	github.com/hashicorp/hcl v1.0.0 // indirect
	github.com/inconshreveable/mousetrap v1.1.0 // indirect
	github.com/jinzhu/inflection v1.0.0 // indirect
	github.com/kballard/go-shellquote v0.0.0-20180428030007-95032a82bc51 // indirect
	github.com/kennygrant/sanitize v1.2.4 // indirect
	github.com/magiconair/properties v1.8.7 // indirect
	github.com/mattn/go-colorable v0.1.13 // indirect
	github.com/mattn/go-isatty v0.0.17 // indirect
	github.com/mattn/go-runewidth v0.0.14 // indirect
	github.com/mgutz/ansi v0.0.0-20200706080929-d51e80ef957d // indirect
	github.com/mtibben/percent v0.2.1 // indirect
	github.com/nu7hatch/gouuid v0.0.0-20131221200532-179d4d0c4d8d // indirect
	github.com/pelletier/go-toml v1.9.5 // indirect
	github.com/pelletier/go-toml/v2 v2.0.6 // indirect
	github.com/rivo/uniseg v0.4.3 // indirect
	github.com/russross/blackfriday/v2 v2.1.0 // indirect
	github.com/saintfish/chardet v0.0.0-20230101081208-5e3ef4b5456d // indirect
	github.com/shurcooL/graphql v0.0.0-20220606043923-3cf50f8a0a29 // indirect
	github.com/spf13/afero v1.9.3 // indirect
	github.com/spf13/jwalterweatherman v1.1.0 // indirect
	github.com/spf13/pflag v1.0.5 // indirect
	github.com/subosito/gotenv v1.4.1 // indirect
	github.com/tadvi/systray v0.0.0-20190226123456-11a2b8fa57af // indirect
	github.com/temoto/robotstxt v1.1.2 // indirect
	golang.org/x/text v0.6.0 // indirect
	google.golang.org/appengine v1.6.7 // indirect
	google.golang.org/protobuf v1.28.1 // indirect
	gopkg.in/ini.v1 v1.67.0 // indirect
	gopkg.in/yaml.v2 v2.4.0 // indirect
)
