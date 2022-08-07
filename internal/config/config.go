package config

import (
	"io"
	"os"

	"github.com/apex/log"
	yaml "gopkg.in/yaml.v3"
)

type Job struct {
	ID        string
	Announce  Announce
	Dockers   []Docker `yaml:"dockers,omitempty" json:"dockers,omitempty"`
	Downloads []Download
	IPSWs     []IPSW
	OTAs      []OTA
	Env       []string `yaml:"env,omitempty" json:"env,omitempty"`
	S3        []S3
	IDAs      []IDA
	Ghidras   []Ghidra
}

type Announce struct {
	Skip       string     `yaml:"skip,omitempty" json:"skip,omitempty"`
	Mattermost Mattermost `yaml:"mattermost,omitempty" json:"mattermost,omitempty"`
}

type Docker struct {
	ID    string   `yaml:"id,omitempty" json:"id,omitempty"`
	Image string   `yaml:"image,omitempty" json:"image,omitempty"`
	Cmd   []string `yaml:"cmd,omitempty" json:"cmd,omitempty"`
}

type Download struct {
}

type IPSW struct {
}

type OTA struct {
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
	Path string `yaml:"path,omitempty" json:"path,omitempty"`
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

type S3 struct {
	Bucket          string   `yaml:"bucket,omitempty" json:"bucket,omitempty"`
	AccessKeyID     string   `yaml:"access_key_id,omitempty" json:"access_key_id,omitempty"`
	SecretAccessKey string   `yaml:"secret_access_key,omitempty" json:"secret_access_key,omitempty"`
	Region          string   `yaml:"region,omitempty" json:"region,omitempty"`
	UseSSL          bool     `yaml:"use_ssl,omitempty" json:"use_ssl,omitempty"`
	Folder          string   `yaml:"folder,omitempty" json:"folder,omitempty"`
	IDs             []string `yaml:"ids,omitempty" json:"ids,omitempty"`
	Endpoint        string   `yaml:"endpoint,omitempty" json:"endpoint,omitempty"`
}

// Load config file.
func Load(file string) (config IPSW, err error) {
	f, err := os.Open(file) // #nosec
	if err != nil {
		return config, err
	}
	defer f.Close()
	log.WithField("file", file).Info("loading config file")
	return LoadReader(f)
}

// LoadReader config via io.Reader.
func LoadReader(fd io.Reader) (config IPSW, err error) {
	data, err := io.ReadAll(fd)
	if err != nil {
		return config, err
	}
	err = yaml.Unmarshal(data, &config)
	log.WithField("config", config).Debug("loaded config file")
	return config, err
}
