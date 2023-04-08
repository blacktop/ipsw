package types

var (
	BuildVersion string
	BuildTime    string
)

// Version is the version struct
type Version struct {
	ApiVersion     string
	OSType         string
	BuilderVersion string
}
