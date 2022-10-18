module github.com/blacktop/ipsw

go 1.19

require (
	github.com/AlecAivazis/survey/v2 v2.3.6
	github.com/PuerkitoBio/goquery v1.8.0
	github.com/apex/log v1.9.0
	github.com/blacktop/arm64-cgo v1.0.55
	github.com/blacktop/go-macho v1.1.100
	github.com/blacktop/go-plist v1.0.1
	github.com/blacktop/lzfse-cgo v1.1.18
	github.com/blacktop/lzss v0.1.1
	github.com/blacktop/ranger v1.0.3
	github.com/caarlos0/ctrlc v1.2.0
	github.com/dustin/go-humanize v1.0.0
	github.com/fatih/color v1.13.0
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
	github.com/shurcooL/githubv4 v0.0.0-20220922232305-70b4d362a8cb
	github.com/spf13/cast v1.5.0
	github.com/spf13/cobra v1.6.0
	github.com/spf13/viper v1.13.0
	github.com/ulikunitz/xz v0.5.10
	github.com/unicorn-engine/unicorn v0.0.0-20220707154909-6c1cbef6ac50
	github.com/vbauerster/mpb/v7 v7.5.3
	github.com/xi2/xz v0.0.0-20171230120015-48954b6210f8
	golang.org/x/crypto v0.0.0-20221012134737-56aed061732a
	golang.org/x/net v0.0.0-20221017152216-f25eb7ecb193
	golang.org/x/oauth2 v0.0.0-20221014153046-6fdb5e3db783
	golang.org/x/sync v0.1.0
	golang.org/x/sys v0.1.0
	gopkg.in/yaml.v3 v3.0.1
)

// replace github.com/blacktop/go-macho => ../go-macho
// replace github.com/blacktop/arm64-cgo => ../arm64-cgo
// replace github.com/unicorn-engine/unicorn => ./unicorn2

require (
	github.com/VividCortex/ewma v1.2.0 // indirect
	github.com/acarl005/stripansi v0.0.0-20180116102854-5a71ef0e047d // indirect
	github.com/andybalholm/cascadia v1.3.1 // indirect
	github.com/antchfx/htmlquery v1.2.5 // indirect
	github.com/antchfx/xmlquery v1.3.12 // indirect
	github.com/antchfx/xpath v1.2.1 // indirect
	github.com/blacktop/go-dwarf v1.0.7 // indirect
	github.com/cpuguy83/go-md2man/v2 v2.0.2 // indirect
	github.com/fsnotify/fsnotify v1.6.0 // indirect
	github.com/go-toast/toast v0.0.0-20190211030409-01e6764cf0a4 // indirect
	github.com/gobwas/glob v0.2.3 // indirect
	github.com/godbus/dbus/v5 v5.1.0 // indirect
	github.com/golang/groupcache v0.0.0-20210331224755-41bb18bfe9da // indirect
	github.com/golang/protobuf v1.5.2 // indirect
	github.com/hashicorp/hcl v1.0.0 // indirect
	github.com/inconshreveable/mousetrap v1.0.1 // indirect
	github.com/jinzhu/inflection v1.0.0 // indirect
	github.com/kballard/go-shellquote v0.0.0-20180428030007-95032a82bc51 // indirect
	github.com/kennygrant/sanitize v1.2.4 // indirect
	github.com/magiconair/properties v1.8.6 // indirect
	github.com/mattn/go-colorable v0.1.13 // indirect
	github.com/mattn/go-isatty v0.0.16 // indirect
	github.com/mattn/go-runewidth v0.0.14 // indirect
	github.com/mgutz/ansi v0.0.0-20200706080929-d51e80ef957d // indirect
	github.com/nu7hatch/gouuid v0.0.0-20131221200532-179d4d0c4d8d // indirect
	github.com/pelletier/go-toml v1.9.5 // indirect
	github.com/pelletier/go-toml/v2 v2.0.5 // indirect
	github.com/rivo/uniseg v0.4.2 // indirect
	github.com/russross/blackfriday/v2 v2.1.0 // indirect
	github.com/saintfish/chardet v0.0.0-20120816061221-3af4cd4741ca // indirect
	github.com/shurcooL/graphql v0.0.0-20220606043923-3cf50f8a0a29 // indirect
	github.com/spf13/afero v1.9.2 // indirect
	github.com/spf13/jwalterweatherman v1.1.0 // indirect
	github.com/spf13/pflag v1.0.5 // indirect
	github.com/subosito/gotenv v1.4.1 // indirect
	github.com/tadvi/systray v0.0.0-20190226123456-11a2b8fa57af // indirect
	github.com/temoto/robotstxt v1.1.2 // indirect
	golang.org/x/term v0.0.0-20221017184919-83659145692c // indirect
	golang.org/x/text v0.4.0 // indirect
	google.golang.org/appengine v1.6.7 // indirect
	google.golang.org/protobuf v1.28.1 // indirect
	gopkg.in/ini.v1 v1.67.0 // indirect
	gopkg.in/yaml.v2 v2.4.0 // indirect
)
