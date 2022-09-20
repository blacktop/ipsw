package config

import (
	"encoding/json"
	"io"
	"os"
	"time"

	"github.com/apex/log"
	"github.com/invopop/jsonschema"
	yaml "gopkg.in/yaml.v3"
)

type Job struct {
	ID            string      `yaml:"id,omitempty" json:"id,omitempty"`
	Env           []string    `yaml:"env,omitempty" json:"env,omitempty"`
	Download      Download    `yaml:"download,omitempty" json:"download,omitempty"`
	Extract       Extract     `yaml:"extract,omitempty" json:"extract,omitempty"`
	Dockers       []Docker    `yaml:"dockers,omitempty" json:"dockers,omitempty"`
	IDA           []IDA       `yaml:"ida,omitempty" json:"ida,omitempty"`
	Ghidra        []Ghidra    `yaml:"ghidra,omitempty" json:"ghidra,omitempty"`
	Symbols       []Symbol    `yaml:"symbols,omitempty" json:"symbols,omitempty"`
	Strings       []String    `yaml:"strings,omitempty" json:"strings,omitempty"`
	TBDs          []TBD       `yaml:"tbds,omitempty" json:"tbds,omitempty"`
	Headers       []Header    `yaml:"headers,omitempty" json:"headers,omitempty"`
	Sandboxes     []Sandbox   `yaml:"sandboxes,omitempty" json:"sandboxes,omitempty"`
	Diffs         []Diff      `yaml:"diffs,omitempty" json:"diffs,omitempty"`
	Archives      []Archive   `yaml:"archives,omitempty" json:"archives,omitempty"`
	Artifactories []Upload    `yaml:"artifactories,omitempty" json:"artifactories,omitempty"`
	Uploads       []Upload    `yaml:"uploads,omitempty" json:"uploads,omitempty"`
	Blobs         []Blob      `yaml:"blobs,omitempty" json:"blobs,omitempty"`
	Publishers    []Publisher `yaml:"publishers,omitempty" json:"publishers,omitempty"`
	Announce      Announce    `yaml:"announce,omitempty" json:"announce,omitempty"`
}

type Download struct {
	IPSW []IPSW `yaml:"ipsw,omitempty" json:"ipsw,omitempty"`
	OTA  []OTA  `yaml:"ota,omitempty" json:"ota,omitempty"`
}

type IPSW struct {
}

type OTA struct {
}

// File is a file inside an archive.
type File struct {
	Source      string   `yaml:"src,omitempty" json:"src,omitempty"`
	Destination string   `yaml:"dst,omitempty" json:"dst,omitempty"`
	StripParent bool     `yaml:"strip_parent,omitempty" json:"strip_parent,omitempty"`
	Info        FileInfo `yaml:"info,omitempty" json:"info,omitempty"`
}

// FileInfo is the file info of a file.
type FileInfo struct {
	Owner string      `yaml:"owner,omitempty" json:"owner,omitempty"`
	Group string      `yaml:"group,omitempty" json:"group,omitempty"`
	Mode  os.FileMode `yaml:"mode,omitempty" json:"mode,omitempty"`
	MTime time.Time   `yaml:"mtime,omitempty" json:"mtime,omitempty"`
}

// UnmarshalYAML is a custom unmarshaler that wraps strings in arrays.
func (f *File) UnmarshalYAML(unmarshal func(interface{}) error) error {
	type t File
	var str string
	if err := unmarshal(&str); err == nil {
		*f = File{Source: str}
		return nil
	}

	var file t
	if err := unmarshal(&file); err != nil {
		return err
	}
	*f = File(file)
	return nil
}

func (f File) JSONSchema() *jsonschema.Schema {
	type t File
	reflector := jsonschema.Reflector{
		ExpandedStruct: true,
	}
	schema := reflector.Reflect(&t{})
	return &jsonschema.Schema{
		OneOf: []*jsonschema.Schema{
			{
				Type: "string",
			},
			schema,
		},
	}
}

// Archive config used for the archive.
type Archive struct {
	ID                        string            `yaml:"id,omitempty" json:"id,omitempty"`
	Builds                    []string          `yaml:"builds,omitempty" json:"builds,omitempty"`
	NameTemplate              string            `yaml:"name_template,omitempty" json:"name_template,omitempty"`
	Replacements              map[string]string `yaml:"replacements,omitempty" json:"replacements,omitempty"`
	Format                    string            `yaml:"format,omitempty" json:"format,omitempty"`
	WrapInDirectory           string            `yaml:"wrap_in_directory,omitempty" json:"wrap_in_directory,omitempty" jsonschema:"oneof_type=string;boolean"`
	StripParentBinaryFolder   bool              `yaml:"strip_parent_binary_folder,omitempty" json:"strip_parent_binary_folder,omitempty"`
	Files                     []File            `yaml:"files,omitempty" json:"files,omitempty"`
	Meta                      bool              `yaml:"meta,omitempty" json:"meta,omitempty"`
	AllowDifferentBinaryCount bool              `yaml:"allow_different_binary_count,omitempty" json:"allow_different_binary_count,omitempty"`
}

type Extract struct {
	ID          string `yaml:"id,omitempty" json:"id,omitempty"`
	Kernelcache bool   `yaml:"kernelcache,omitempty" json:"kernelcache,omitempty"`
	DSC         bool   `yaml:"dyld_share_cache,omitempty" json:"dyld_share_cache,omitempty"`
	Pattern     string `yaml:"pattern,omitempty" json:"pattern,omitempty"`
}

type Docker struct {
	ID    string   `yaml:"id,omitempty" json:"id,omitempty"`
	Image string   `yaml:"image,omitempty" json:"image,omitempty"`
	Cmd   []string `yaml:"cmd,omitempty" json:"cmd,omitempty"`
}

type IDA struct {
	AutoAnalyze bool
	AutoAccept  bool
	BatchMode   bool
	DeleteDB    bool
	Compiler    string
	Database    string
	CompressDB  bool
	Processor   string

	ScriptArgs []string
	PluginArgs []string
	FileType   string

	InputFile    string
	EnableGUI    bool
	ShowIDALog   bool
	LogFile      string
	TempDatabase bool
	ExtraArgs    []string
}

type Ghidra struct {
	Path string   `yaml:"path,omitempty" json:"path,omitempty"`
	Args []string `yaml:"args,omitempty" json:"args,omitempty"`
}

type Symbol struct {
	Name  string `yaml:"name,omitempty" json:"name,omitempty"`
	Dylib string `yaml:"dylib,omitempty" json:"dylib,omitempty"`
}

type String struct {
	Name  string `yaml:"name,omitempty" json:"name,omitempty"`
	Dylib string `yaml:"dylib,omitempty" json:"dylib,omitempty"`
}

type TBD struct {
	ID    string `yaml:"id,omitempty" json:"id,omitempty"`
	Dylib string `yaml:"dylib,omitempty" json:"dylib,omitempty"`
}

type Header struct {
	ID    string `yaml:"id,omitempty" json:"id,omitempty"`
	Dylib string `yaml:"dylib,omitempty" json:"dylib,omitempty"`
}

type Sandbox struct {
	ID      string `yaml:"id,omitempty" json:"id,omitempty"`
	Profile string `yaml:"profile,omitempty" json:"profile,omitempty"`
}

type Diff struct {
	ID   string `yaml:"id,omitempty" json:"id,omitempty"`
	Type string `yaml:"type,omitempty" json:"type,omitempty"`
}

// ExtraFile on a release.
type ExtraFile struct {
	Glob         string `yaml:"glob,omitempty" json:"glob,omitempty"`
	NameTemplate string `yaml:"name_template,omitempty" json:"name_template,omitempty"`
}

// Filters config.
type Filters struct {
	Exclude []string `yaml:"exclude,omitempty" json:"exclude,omitempty"`
}

// Blob contains config for GO CDK blob.
type Blob struct {
	Bucket     string      `yaml:"bucket,omitempty" json:"bucket,omitempty"`
	Provider   string      `yaml:"provider,omitempty" json:"provider,omitempty"`
	Region     string      `yaml:"region,omitempty" json:"region,omitempty"`
	DisableSSL bool        `yaml:"disableSSL,omitempty" json:"disableSSL,omitempty"` // nolint:tagliatelle // TODO(caarlos0): rename to disable_ssl
	Folder     string      `yaml:"folder,omitempty" json:"folder,omitempty"`
	KMSKey     string      `yaml:"kmskey,omitempty" json:"kmskey,omitempty"`
	IDs        []string    `yaml:"ids,omitempty" json:"ids,omitempty"`
	Endpoint   string      `yaml:"endpoint,omitempty" json:"endpoint,omitempty"` // used for minio for example
	ExtraFiles []ExtraFile `yaml:"extra_files,omitempty" json:"extra_files,omitempty"`
}

// Upload configuration.
type Upload struct {
	Name               string            `yaml:"name,omitempty" json:"name,omitempty"`
	IDs                []string          `yaml:"ids,omitempty" json:"ids,omitempty"`
	Exts               []string          `yaml:"exts,omitempty" json:"exts,omitempty"`
	Target             string            `yaml:"target,omitempty" json:"target,omitempty"`
	Username           string            `yaml:"username,omitempty" json:"username,omitempty"`
	Mode               string            `yaml:"mode,omitempty" json:"mode,omitempty"`
	Method             string            `yaml:"method,omitempty" json:"method,omitempty"`
	ChecksumHeader     string            `yaml:"checksum_header,omitempty" json:"checksum_header,omitempty"`
	ClientX509Cert     string            `yaml:"client_x509_cert" json:"client_x509_cert"`
	ClientX509Key      string            `yaml:"client_x509_key" json:"client_x509_key"`
	TrustedCerts       string            `yaml:"trusted_certificates,omitempty" json:"trusted_certificates,omitempty"`
	Checksum           bool              `yaml:"checksum,omitempty" json:"checksum,omitempty"`
	Signature          bool              `yaml:"signature,omitempty" json:"signature,omitempty"`
	CustomArtifactName bool              `yaml:"custom_artifact_name,omitempty" json:"custom_artifact_name,omitempty"`
	CustomHeaders      map[string]string `yaml:"custom_headers,omitempty" json:"custom_headers,omitempty"`
}

// Publisher configuration.
type Publisher struct {
	Name       string      `yaml:"name,omitempty" json:"name,omitempty"`
	IDs        []string    `yaml:"ids,omitempty" json:"ids,omitempty"`
	Checksum   bool        `yaml:"checksum,omitempty" json:"checksum,omitempty"`
	Signature  bool        `yaml:"signature,omitempty" json:"signature,omitempty"`
	Dir        string      `yaml:"dir,omitempty" json:"dir,omitempty"`
	Cmd        string      `yaml:"cmd,omitempty" json:"cmd,omitempty"`
	Env        []string    `yaml:"env,omitempty" json:"env,omitempty"`
	ExtraFiles []ExtraFile `yaml:"extra_files,omitempty" json:"extra_files,omitempty"`
}

type Announce struct {
	Skip       string     `yaml:"skip,omitempty" json:"skip,omitempty"`
	Mattermost Mattermost `yaml:"mattermost,omitempty" json:"mattermost,omitempty"`
}

type Webhook struct {
	Enabled         bool              `yaml:"enabled,omitempty" json:"enabled,omitempty"`
	SkipTLSVerify   bool              `yaml:"skip_tls_verify,omitempty" json:"skip_tls_verify,omitempty"`
	MessageTemplate string            `yaml:"message_template,omitempty" json:"message_template,omitempty"`
	EndpointURL     string            `yaml:"endpoint_url,omitempty" json:"endpoint_url,omitempty"`
	Headers         map[string]string `yaml:"headers,omitempty" json:"headers,omitempty"`
	ContentType     string            `yaml:"content_type,omitempty" json:"content_type,omitempty"`
}

type Discord struct {
	Enabled         bool   `yaml:"enabled,omitempty" json:"enabled,omitempty"`
	MessageTemplate string `yaml:"message_template,omitempty" json:"message_template,omitempty"`
	Author          string `yaml:"author,omitempty" json:"author,omitempty"`
	Color           string `yaml:"color,omitempty" json:"color,omitempty"`
	IconURL         string `yaml:"icon_url,omitempty" json:"icon_url,omitempty"`
}

type Mattermost struct {
	Enabled         bool   `yaml:"enabled,omitempty" json:"enabled,omitempty"`
	MessageTemplate string `yaml:"message_template,omitempty" json:"message_template,omitempty"`
	TitleTemplate   string `yaml:"title_template,omitempty" json:"title_template,omitempty"`
	Color           string `yaml:"color,omitempty" json:"color,omitempty"`
	Channel         string `yaml:"channel,omitempty" json:"channel,omitempty"`
	Username        string `yaml:"username,omitempty" json:"username,omitempty"`
	IconEmoji       string `yaml:"icon_emoji,omitempty" json:"icon_emoji,omitempty"`
	IconURL         string `yaml:"icon_url,omitempty" json:"icon_url,omitempty"`
}

type Slack struct {
	Enabled         bool              `yaml:"enabled,omitempty" json:"enabled,omitempty"`
	MessageTemplate string            `yaml:"message_template,omitempty" json:"message_template,omitempty"`
	Channel         string            `yaml:"channel,omitempty" json:"channel,omitempty"`
	Username        string            `yaml:"username,omitempty" json:"username,omitempty"`
	IconEmoji       string            `yaml:"icon_emoji,omitempty" json:"icon_emoji,omitempty"`
	IconURL         string            `yaml:"icon_url,omitempty" json:"icon_url,omitempty"`
	Blocks          []SlackBlock      `yaml:"blocks,omitempty" json:"blocks,omitempty"`
	Attachments     []SlackAttachment `yaml:"attachments,omitempty" json:"attachments,omitempty"`
}

// Load config file.
func Load(file string) (config Job, err error) {
	f, err := os.Open(file) // #nosec
	if err != nil {
		return config, err
	}
	defer f.Close()
	log.WithField("file", file).Info("loading config file")
	return LoadReader(f)
}

// LoadReader config via io.Reader.
func LoadReader(fd io.Reader) (config Job, err error) {
	data, err := io.ReadAll(fd)
	if err != nil {
		return config, err
	}
	err = yaml.Unmarshal(data, &config)
	log.WithField("config", config).Debug("loaded config file")
	return config, err
}

// SlackBlock represents the untyped structure of a rich slack message layout.
type SlackBlock struct {
	Internal interface{}
}

// UnmarshalYAML is a custom unmarshaler that unmarshals a YAML slack block as untyped interface{}.
func (a *SlackBlock) UnmarshalYAML(unmarshal func(interface{}) error) error {
	var yamlv2 interface{}
	if err := unmarshal(&yamlv2); err != nil {
		return err
	}

	a.Internal = yamlv2

	return nil
}

// MarshalJSON marshals a slack block as JSON.
func (a SlackBlock) MarshalJSON() ([]byte, error) {
	return json.Marshal(a.Internal)
}

// SlackAttachment represents the untyped structure of a slack message attachment.
type SlackAttachment struct {
	Internal interface{}
}

// UnmarshalYAML is a custom unmarshaler that unmarshals a YAML slack attachment as untyped interface{}.
func (a *SlackAttachment) UnmarshalYAML(unmarshal func(interface{}) error) error {
	var yamlv2 interface{}
	if err := unmarshal(&yamlv2); err != nil {
		return err
	}

	a.Internal = yamlv2

	return nil
}

// MarshalJSON marshals a slack attachment as JSON.
func (a SlackAttachment) MarshalJSON() ([]byte, error) {
	return json.Marshal(a.Internal)
}
