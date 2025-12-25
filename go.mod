module github.com/blacktop/ipsw

go 1.25.3

tool (
	github.com/caarlos0/svu/v3
	github.com/spf13/cobra-cli
	golang.org/x/tools/cmd/stringer
)

require (
	github.com/99designs/keyring v1.2.2
	github.com/AlecAivazis/survey/v2 v2.3.7
	github.com/MakeNowJust/heredoc/v2 v2.0.1
	github.com/PuerkitoBio/goquery v1.11.0
	github.com/alecthomas/chroma/v2 v2.21.1
	github.com/anthropics/anthropic-sdk-go v1.19.0
	github.com/apex/log v1.9.0
	github.com/aymanbagabas/go-udiff v0.3.1
	github.com/blacktop/arm64-cgo v1.0.67
	github.com/blacktop/go-apfs v1.0.27
	github.com/blacktop/go-dwarf v1.0.14
	github.com/blacktop/go-macho v1.1.258
	github.com/blacktop/go-plist v1.0.2
	github.com/blacktop/go-termimg v0.1.24
	github.com/blacktop/lzfse-cgo v1.2.0
	github.com/blacktop/lzss v0.1.8
	github.com/blacktop/ranger v1.0.3
	github.com/boombuler/barcode v1.1.0
	github.com/briandowns/spinner v1.23.2
	github.com/caarlos0/ctrlc v1.2.0
	github.com/caarlos0/env/v8 v8.0.0
	github.com/charmbracelet/bubbles v0.21.0
	github.com/charmbracelet/bubbletea v1.3.10
	github.com/charmbracelet/lipgloss v1.1.0
	github.com/cloudflare/circl v1.6.2
	github.com/coder/acp-go-sdk v0.6.3
	github.com/disintegration/imaging v1.6.2
	github.com/docker/docker v28.5.2+incompatible
	github.com/dominikbraun/graph v0.23.0
	github.com/dustin/go-humanize v1.0.1
	github.com/fatih/color v1.18.0
	github.com/frida/frida-go v1.0.1-0.20251208071928-b051ae61cac6
	github.com/fsnotify/fsnotify v1.9.0
	github.com/fullsailor/pkcs7 v0.0.0-20190404230743-d7302db945fa
	github.com/gen2brain/beeep v0.11.2
	github.com/gin-gonic/gin v1.11.0
	github.com/glebarez/sqlite v1.11.0
	github.com/go-git/go-git/v5 v5.16.4
	github.com/go-viper/mapstructure/v2 v2.4.0
	github.com/gocolly/colly/v2 v2.3.0
	github.com/golang-jwt/jwt/v5 v5.3.0
	github.com/gomarkdown/markdown v0.0.0-20250810172220-2e2c11897d1a
	github.com/google/gousb v1.1.3
	github.com/google/uuid v1.6.0
	github.com/hashicorp/go-version v1.8.0
	github.com/hashicorp/golang-lru/v2 v2.0.7
	github.com/invopop/jsonschema v0.13.0
	github.com/mattn/go-mastodon v0.0.10
	github.com/mitchellh/mapstructure v1.5.0
	github.com/ollama/ollama v0.13.5
	github.com/openai/openai-go v1.12.0
	github.com/opencontainers/image-spec v1.1.1
	github.com/pkg/errors v0.9.1
	github.com/sergi/go-diff v1.4.0
	github.com/shurcooL/githubv4 v0.0.0-20240727222349-48295856cce7
	github.com/spf13/cast v1.10.0
	github.com/spf13/cobra v1.10.2
	github.com/spf13/pflag v1.0.10
	github.com/spf13/viper v1.21.0
	github.com/strukturag/libheif-go v0.0.0-20250130134905-55b3482bea15
	github.com/twmb/murmur3 v1.1.8
	github.com/ulikunitz/xz v0.5.15
	github.com/unicorn-engine/unicorn v0.0.0-20250911131444-c24c9ebe773c
	github.com/vbauerster/mpb/v8 v8.11.3
	github.com/xi2/xz v0.0.0-20171230120015-48954b6210f8
	golang.org/x/crypto v0.46.0
	golang.org/x/exp v0.0.0-20251219203646-944ab1f22d93
	golang.org/x/net v0.48.0
	golang.org/x/oauth2 v0.34.0
	golang.org/x/sync v0.19.0
	golang.org/x/sys v0.39.0
	golang.org/x/term v0.38.0
	google.golang.org/genai v1.40.0
	google.golang.org/protobuf v1.36.11
	gopkg.in/yaml.v3 v3.0.1
	gorm.io/driver/postgres v1.6.0
	gorm.io/gorm v1.31.1
)

require (
	charm.land/lipgloss/v2 v2.0.0-beta.3.0.20251106193318-19329a3e8410 // indirect
	cloud.google.com/go v0.123.0 // indirect
	cloud.google.com/go/auth v0.18.0 // indirect
	cloud.google.com/go/compute/metadata v0.9.0 // indirect
	dario.cat/mergo v1.0.2 // indirect
	git.sr.ht/~jackmordaunt/go-toast v1.1.2 // indirect
	github.com/99designs/go-keychain v0.0.0-20191008050251-8e49817e8af4 // indirect
	github.com/Masterminds/semver/v3 v3.4.0 // indirect
	github.com/Microsoft/go-winio v0.6.2 // indirect
	github.com/ProtonMail/go-crypto v1.3.0 // indirect
	github.com/VividCortex/ewma v1.2.0 // indirect
	github.com/acarl005/stripansi v0.0.0-20180116102854-5a71ef0e047d // indirect
	github.com/andybalholm/cascadia v1.3.3 // indirect
	github.com/antchfx/htmlquery v1.3.5 // indirect
	github.com/antchfx/xmlquery v1.5.0 // indirect
	github.com/antchfx/xpath v1.3.5 // indirect
	github.com/atotto/clipboard v0.1.4 // indirect
	github.com/aymanbagabas/go-osc52/v2 v2.0.1 // indirect
	github.com/bahlo/generic-list-go v0.2.0 // indirect
	github.com/bits-and-blooms/bitset v1.24.4 // indirect
	github.com/buger/jsonparser v1.1.1 // indirect
	github.com/bytedance/gopkg v0.1.3 // indirect
	github.com/bytedance/sonic v1.14.2 // indirect
	github.com/bytedance/sonic/loader v0.4.0 // indirect
	github.com/caarlos0/go-version v0.2.2 // indirect
	github.com/caarlos0/svu/v3 v3.3.0 // indirect
	github.com/cespare/xxhash/v2 v2.3.0 // indirect
	github.com/charmbracelet/colorprofile v0.4.1 // indirect
	github.com/charmbracelet/fang v0.4.4 // indirect
	github.com/charmbracelet/harmonica v0.2.0 // indirect
	github.com/charmbracelet/ultraviolet v0.0.0-20251217160852-6b0c0e26fad9 // indirect
	github.com/charmbracelet/x/ansi v0.11.3 // indirect
	github.com/charmbracelet/x/cellbuf v0.0.14 // indirect
	github.com/charmbracelet/x/exp/charmtone v0.0.0-20251215102626-e0db08df7383 // indirect
	github.com/charmbracelet/x/mosaic v0.0.0-20251215102626-e0db08df7383 // indirect
	github.com/charmbracelet/x/term v0.2.2 // indirect
	github.com/charmbracelet/x/termios v0.1.1 // indirect
	github.com/charmbracelet/x/windows v0.2.2 // indirect
	github.com/clipperhouse/displaywidth v0.6.2 // indirect
	github.com/clipperhouse/stringish v0.1.1 // indirect
	github.com/clipperhouse/uax29/v2 v2.3.0 // indirect
	github.com/cloudwego/base64x v0.1.6 // indirect
	github.com/containerd/errdefs v1.0.0 // indirect
	github.com/containerd/errdefs/pkg v0.3.0 // indirect
	github.com/containerd/log v0.1.0 // indirect
	github.com/cpuguy83/go-md2man/v2 v2.0.7 // indirect
	github.com/creack/pty v1.1.24 // indirect
	github.com/cyphar/filepath-securejoin v0.6.1 // indirect
	github.com/danieljoos/wincred v1.2.3 // indirect
	github.com/distribution/reference v0.6.0 // indirect
	github.com/dlclark/regexp2 v1.11.5 // indirect
	github.com/docker/go-connections v0.6.0 // indirect
	github.com/docker/go-units v0.5.0 // indirect
	github.com/dvsekhvalnov/jose2go v1.8.0 // indirect
	github.com/emirpasic/gods v1.18.1 // indirect
	github.com/erikgeiser/coninput v0.0.0-20211004153227-1c3628e74d0f // indirect
	github.com/esiqveland/notify v0.13.3 // indirect
	github.com/felixge/httpsnoop v1.0.4 // indirect
	github.com/gabriel-vasile/mimetype v1.4.12 // indirect
	github.com/gin-contrib/sse v1.1.0 // indirect
	github.com/glebarez/go-sqlite v1.22.0 // indirect
	github.com/go-git/gcfg v1.5.1-0.20230307220236-3a3c6141e376 // indirect
	github.com/go-git/go-billy/v5 v5.7.0 // indirect
	github.com/go-logr/logr v1.4.3 // indirect
	github.com/go-logr/stdr v1.2.2 // indirect
	github.com/go-ole/go-ole v1.3.0 // indirect
	github.com/go-playground/locales v0.14.1 // indirect
	github.com/go-playground/universal-translator v0.18.1 // indirect
	github.com/go-playground/validator/v10 v10.30.0 // indirect
	github.com/gobwas/glob v0.2.3 // indirect
	github.com/goccy/go-json v0.10.5 // indirect
	github.com/goccy/go-yaml v1.19.1 // indirect
	github.com/godbus/dbus v0.0.0-20190726142602-4481cbc300e2 // indirect
	github.com/godbus/dbus/v5 v5.2.1 // indirect
	github.com/golang/groupcache v0.0.0-20241129210726-2c02b8208cf8 // indirect
	github.com/golang/protobuf v1.5.4 // indirect
	github.com/google/go-cmp v0.7.0 // indirect
	github.com/google/s2a-go v0.1.9 // indirect
	github.com/googleapis/enterprise-certificate-proxy v0.3.7 // indirect
	github.com/googleapis/gax-go/v2 v2.16.0 // indirect
	github.com/gorilla/websocket v1.5.3 // indirect
	github.com/gsterjov/go-libsecret v0.0.0-20161001094733-a6f4afe4910c // indirect
	github.com/inconshreveable/mousetrap v1.1.0 // indirect
	github.com/ink-splatters/darwin-sectrust-compat v0.1.3 // indirect
	github.com/jackc/pgpassfile v1.0.0 // indirect
	github.com/jackc/pgservicefile v0.0.0-20240606120523-5a60cdf6a761 // indirect
	github.com/jackc/pgx/v5 v5.7.6 // indirect
	github.com/jackc/puddle/v2 v2.2.2 // indirect
	github.com/jackmordaunt/icns/v3 v3.0.1 // indirect
	github.com/jbenet/go-context v0.0.0-20150711004518-d14ea06fba99 // indirect
	github.com/jinzhu/inflection v1.0.0 // indirect
	github.com/jinzhu/now v1.1.5 // indirect
	github.com/json-iterator/go v1.1.12 // indirect
	github.com/kballard/go-shellquote v0.0.0-20180428030007-95032a82bc51 // indirect
	github.com/kennygrant/sanitize v1.2.4 // indirect
	github.com/kevinburke/ssh_config v1.4.0 // indirect
	github.com/klauspost/cpuid/v2 v2.3.0 // indirect
	github.com/leodido/go-urn v1.4.0 // indirect
	github.com/lucasb-eyer/go-colorful v1.3.0 // indirect
	github.com/mailru/easyjson v0.9.1 // indirect
	github.com/makeworld-the-better-one/dither/v2 v2.4.0 // indirect
	github.com/mattn/go-colorable v0.1.14 // indirect
	github.com/mattn/go-isatty v0.0.20 // indirect
	github.com/mattn/go-localereader v0.0.1 // indirect
	github.com/mattn/go-runewidth v0.0.19 // indirect
	github.com/mattn/go-sixel v0.0.5 // indirect
	github.com/mgutz/ansi v0.0.0-20200706080929-d51e80ef957d // indirect
	github.com/moby/docker-image-spec v1.3.1 // indirect
	github.com/moby/sys/atomicwriter v0.1.0 // indirect
	github.com/moby/term v0.5.2 // indirect
	github.com/modern-go/concurrent v0.0.0-20180306012644-bacd9c7ef1dd // indirect
	github.com/modern-go/reflect2 v1.0.2 // indirect
	github.com/morikuni/aec v1.1.0 // indirect
	github.com/mtibben/percent v0.2.1 // indirect
	github.com/muesli/ansi v0.0.0-20230316100256-276c6243b2f6 // indirect
	github.com/muesli/cancelreader v0.2.2 // indirect
	github.com/muesli/mango v0.2.0 // indirect
	github.com/muesli/mango-cobra v1.3.0 // indirect
	github.com/muesli/mango-pflag v0.2.0 // indirect
	github.com/muesli/roff v0.1.0 // indirect
	github.com/muesli/termenv v0.16.0 // indirect
	github.com/ncruces/go-strftime v1.0.0 // indirect
	github.com/nfnt/resize v0.0.0-20180221191011-83c6a9932646 // indirect
	github.com/nlnwa/whatwg-url v0.6.2 // indirect
	github.com/opencontainers/go-digest v1.0.0 // indirect
	github.com/pelletier/go-toml/v2 v2.2.4 // indirect
	github.com/pjbgf/sha1cd v0.5.0 // indirect
	github.com/quic-go/qpack v0.6.0 // indirect
	github.com/quic-go/quic-go v0.58.0 // indirect
	github.com/remyoudompheng/bigfft v0.0.0-20230129092748-24d4a6f8daec // indirect
	github.com/rivo/uniseg v0.4.7 // indirect
	github.com/russross/blackfriday/v2 v2.1.0 // indirect
	github.com/sagikazarmark/locafero v0.12.0 // indirect
	github.com/sahilm/fuzzy v0.1.1 // indirect
	github.com/saintfish/chardet v0.0.0-20230101081208-5e3ef4b5456d // indirect
	github.com/sergeymakinen/go-bmp v1.0.0 // indirect
	github.com/sergeymakinen/go-ico v1.0.0 // indirect
	github.com/shurcooL/graphql v0.0.0-20230722043721-ed46e5a46466 // indirect
	github.com/skeema/knownhosts v1.3.2 // indirect
	github.com/soniakeys/quant v1.0.0 // indirect
	github.com/spf13/afero v1.15.0 // indirect
	github.com/spf13/cobra-cli v1.3.0 // indirect
	github.com/subosito/gotenv v1.6.0 // indirect
	github.com/tadvi/systray v0.0.0-20190226123456-11a2b8fa57af // indirect
	github.com/temoto/robotstxt v1.1.2 // indirect
	github.com/tidwall/gjson v1.18.0 // indirect
	github.com/tidwall/match v1.2.0 // indirect
	github.com/tidwall/pretty v1.2.1 // indirect
	github.com/tidwall/sjson v1.2.5 // indirect
	github.com/tomnomnom/linkheader v0.0.0-20250811210735-e5fe3b51442e // indirect
	github.com/twitchyliquid64/golang-asm v0.15.1 // indirect
	github.com/ugorji/go/codec v1.3.1 // indirect
	github.com/vbauerster/mpb/v7 v7.5.3 // indirect
	github.com/wk8/go-ordered-map/v2 v2.1.8 // indirect
	github.com/xanzy/ssh-agent v0.3.3 // indirect
	github.com/xo/terminfo v0.0.0-20220910002029-abceb7e1c41e // indirect
	go.opentelemetry.io/auto/sdk v1.2.1 // indirect
	go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp v0.64.0 // indirect
	go.opentelemetry.io/otel v1.39.0 // indirect
	go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp v1.39.0 // indirect
	go.opentelemetry.io/otel/metric v1.39.0 // indirect
	go.opentelemetry.io/otel/trace v1.39.0 // indirect
	go.uber.org/mock v0.6.0 // indirect
	go.yaml.in/yaml/v3 v3.0.4 // indirect
	golang.org/x/arch v0.23.0 // indirect
	golang.org/x/image v0.34.0 // indirect
	golang.org/x/mod v0.31.0 // indirect
	golang.org/x/text v0.32.0 // indirect
	golang.org/x/tools v0.40.0 // indirect
	google.golang.org/appengine v1.6.8 // indirect
	google.golang.org/genproto/googleapis/api v0.0.0-20251222181119-0a764e51fe1b // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20251222181119-0a764e51fe1b // indirect
	google.golang.org/grpc v1.77.0 // indirect
	gopkg.in/warnings.v0 v0.1.2 // indirect
	gotest.tools/v3 v3.5.2 // indirect
	modernc.org/libc v1.67.1 // indirect
	modernc.org/mathutil v1.7.1 // indirect
	modernc.org/memory v1.11.0 // indirect
	modernc.org/sqlite v1.41.0 // indirect
)
