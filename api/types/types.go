package types

var (
	BuildVersion string
	BuildTime    string
)

// Version is the version struct
type Version struct {
	APIVersion     string `json:"api_version,omitempty"`
	OSType         string `json:"os_type,omitempty"`
	BuilderVersion string `json:"builder_version,omitempty"`
}

// swagger:response genericError
type GenericError struct {
	Error string `json:"error"`
}
