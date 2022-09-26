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
	github.com/spf13/cobra v1.5.0
	github.com/spf13/viper v1.13.0
	github.com/ulikunitz/xz v0.5.10
	github.com/unicorn-engine/unicorn v0.0.0-20220707154909-6c1cbef6ac50
	github.com/vbauerster/mpb/v7 v7.5.3
	github.com/xi2/xz v0.0.0-20171230120015-48954b6210f8
	golang.org/x/crypto v0.0.0-20220924013350-4ba4fb4dd9e7
	golang.org/x/net v0.0.0-20220923203811-8be639271d50
	golang.org/x/oauth2 v0.0.0-20220909003341-f21342109be1
	golang.org/x/sync v0.0.0-20220923202941-7f9b1623fab7
	golang.org/x/sys v0.0.0-20220919091848-fb04ddd9f9c8
	gopkg.in/yaml.v3 v3.0.1
)

// replace github.com/blacktop/go-macho => ../go-macho
// replace github.com/blacktop/arm64-cgo => ../arm64-cgo
// replace github.com/unicorn-engine/unicorn => ./unicorn2

require (
	github.com/Masterminds/semver/v3 v3.1.1
	github.com/caarlos0/env/v6 v6.9.3
	github.com/caarlos0/log v0.1.1
	github.com/charmbracelet/lipgloss v0.5.1-0.20220615005615-2e17a8a06096
	github.com/docker/docker v20.10.17+incompatible
	github.com/goreleaser/fileglob v1.3.0
	github.com/invopop/jsonschema v0.5.0
	gocloud.dev v0.24.0
)

require (
	cloud.google.com/go v0.102.0 // indirect
	cloud.google.com/go/compute v1.7.0 // indirect
	cloud.google.com/go/iam v0.3.0 // indirect
	cloud.google.com/go/kms v0.1.0 // indirect
	cloud.google.com/go/storage v1.22.1 // indirect
	github.com/Azure/azure-pipeline-go v0.2.3 // indirect
	github.com/Azure/azure-sdk-for-go v57.0.0+incompatible // indirect
	github.com/Azure/azure-storage-blob-go v0.14.0 // indirect
	github.com/Azure/go-autorest v14.2.0+incompatible // indirect
	github.com/Azure/go-autorest/autorest v0.11.20 // indirect
	github.com/Azure/go-autorest/autorest/adal v0.9.15 // indirect
	github.com/Azure/go-autorest/autorest/azure/auth v0.5.8 // indirect
	github.com/Azure/go-autorest/autorest/azure/cli v0.4.3 // indirect
	github.com/Azure/go-autorest/autorest/date v0.3.0 // indirect
	github.com/Azure/go-autorest/autorest/to v0.4.0 // indirect
	github.com/Azure/go-autorest/autorest/validation v0.3.1 // indirect
	github.com/Azure/go-autorest/logger v0.2.1 // indirect
	github.com/Azure/go-autorest/tracing v0.6.0 // indirect
	github.com/Microsoft/go-winio v0.5.0 // indirect
	github.com/VividCortex/ewma v1.2.0 // indirect
	github.com/acarl005/stripansi v0.0.0-20180116102854-5a71ef0e047d // indirect
	github.com/andybalholm/cascadia v1.3.1 // indirect
	github.com/antchfx/htmlquery v1.2.5 // indirect
	github.com/antchfx/xmlquery v1.3.12 // indirect
	github.com/antchfx/xpath v1.2.1 // indirect
	github.com/aws/aws-sdk-go v1.40.34 // indirect
	github.com/aws/aws-sdk-go-v2 v1.9.0 // indirect
	github.com/aws/aws-sdk-go-v2/config v1.7.0 // indirect
	github.com/aws/aws-sdk-go-v2/credentials v1.4.0 // indirect
	github.com/aws/aws-sdk-go-v2/feature/ec2/imds v1.5.0 // indirect
	github.com/aws/aws-sdk-go-v2/internal/ini v1.2.2 // indirect
	github.com/aws/aws-sdk-go-v2/service/internal/presigned-url v1.3.0 // indirect
	github.com/aws/aws-sdk-go-v2/service/kms v1.5.0 // indirect
	github.com/aws/aws-sdk-go-v2/service/sso v1.4.0 // indirect
	github.com/aws/aws-sdk-go-v2/service/sts v1.7.0 // indirect
	github.com/aws/smithy-go v1.8.0 // indirect
	github.com/aymanbagabas/go-osc52 v1.0.3 // indirect
	github.com/blacktop/go-dwarf v1.0.7 // indirect
	github.com/cpuguy83/go-md2man/v2 v2.0.2 // indirect
	github.com/dimchansky/utfbom v1.1.1 // indirect
	github.com/docker/distribution v2.8.1+incompatible // indirect
	github.com/docker/go-connections v0.4.0 // indirect
	github.com/docker/go-units v0.4.0 // indirect
	github.com/fsnotify/fsnotify v1.5.4 // indirect
	github.com/go-toast/toast v0.0.0-20190211030409-01e6764cf0a4 // indirect
	github.com/gobwas/glob v0.2.3 // indirect
	github.com/godbus/dbus/v5 v5.1.0 // indirect
	github.com/gogo/protobuf v1.3.2 // indirect
	github.com/golang-jwt/jwt/v4 v4.0.0 // indirect
	github.com/golang/groupcache v0.0.0-20210331224755-41bb18bfe9da // indirect
	github.com/golang/protobuf v1.5.2 // indirect
	github.com/google/go-cmp v0.5.8 // indirect
	github.com/google/uuid v1.3.0 // indirect
	github.com/google/wire v0.5.0 // indirect
	github.com/googleapis/enterprise-certificate-proxy v0.0.0-20220520183353-fd19c99a87aa // indirect
	github.com/googleapis/gax-go/v2 v2.4.0 // indirect
	github.com/googleapis/go-type-adapters v1.0.0 // indirect
	github.com/hashicorp/hcl v1.0.0 // indirect
	github.com/iancoleman/orderedmap v0.2.0 // indirect
	github.com/inconshreveable/mousetrap v1.0.1 // indirect
	github.com/jinzhu/inflection v1.0.0 // indirect
	github.com/jmespath/go-jmespath v0.4.0 // indirect
	github.com/kballard/go-shellquote v0.0.0-20180428030007-95032a82bc51 // indirect
	github.com/kennygrant/sanitize v1.2.4 // indirect
	github.com/lucasb-eyer/go-colorful v1.2.0 // indirect
	github.com/magiconair/properties v1.8.6 // indirect
	github.com/mattn/go-colorable v0.1.13 // indirect
	github.com/mattn/go-ieproxy v0.0.1 // indirect
	github.com/mattn/go-isatty v0.0.16 // indirect
	github.com/mattn/go-runewidth v0.0.14 // indirect
	github.com/mgutz/ansi v0.0.0-20200706080929-d51e80ef957d // indirect
	github.com/moby/term v0.0.0-20210619224110-3f7ff695adc6 // indirect
	github.com/morikuni/aec v1.0.0 // indirect
	github.com/muesli/reflow v0.2.1-0.20210115123740-9e1d0d53df68 // indirect
	github.com/muesli/termenv v0.12.1-0.20220615005108-4e9068de9898 // indirect
	github.com/nu7hatch/gouuid v0.0.0-20131221200532-179d4d0c4d8d // indirect
	github.com/opencontainers/go-digest v1.0.0 // indirect
	github.com/opencontainers/image-spec v1.0.2 // indirect
	github.com/pelletier/go-toml v1.9.5 // indirect
	github.com/pelletier/go-toml/v2 v2.0.5 // indirect
	github.com/rivo/uniseg v0.4.2 // indirect
	github.com/russross/blackfriday/v2 v2.1.0 // indirect
	github.com/saintfish/chardet v0.0.0-20120816061221-3af4cd4741ca // indirect
	github.com/shurcooL/graphql v0.0.0-20220606043923-3cf50f8a0a29 // indirect
	github.com/sirupsen/logrus v1.9.0 // indirect
	github.com/spf13/afero v1.9.2 // indirect
	github.com/spf13/jwalterweatherman v1.1.0 // indirect
	github.com/spf13/pflag v1.0.5 // indirect
	github.com/subosito/gotenv v1.4.1 // indirect
	github.com/tadvi/systray v0.0.0-20190226123456-11a2b8fa57af // indirect
	github.com/temoto/robotstxt v1.1.2 // indirect
	golang.org/x/term v0.0.0-20220919170432-7a66f970e087 // indirect
	golang.org/x/text v0.3.7 // indirect
	golang.org/x/time v0.0.0-20220411224347-583f2d630306 // indirect
	golang.org/x/xerrors v0.0.0-20220609144429-65e65417b02f // indirect
	google.golang.org/api v0.84.0 // indirect
	google.golang.org/appengine v1.6.7 // indirect
	google.golang.org/genproto v0.0.0-20220616135557-88e70c0c3a90 // indirect
	google.golang.org/grpc v1.47.0 // indirect
	google.golang.org/protobuf v1.28.1 // indirect
	gopkg.in/ini.v1 v1.67.0 // indirect
	gopkg.in/yaml.v2 v2.4.0 // indirect
	gotest.tools/v3 v3.0.2 // indirect
)
