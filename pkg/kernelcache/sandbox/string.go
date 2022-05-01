package sandbox

const (
	STATE_UNKNOWN               = 0
	STATE_TOKEN_BYTE_READ       = 1
	STATE_CONCAT_BYTE_READ      = 2
	STATE_CONCAT_SAVE_BYTE_READ = 3
	STATE_END_BYTE_READ         = 4
	STATE_SPLIT_BYTE_READ       = 5
	STATE_TOKEN_READ            = 6
	STATE_RANGE_BYTE_READ       = 7
	STATE_CONSTANT_READ         = 8
	STATE_SINGLE_BYTE_READ      = 9
	STATE_PLUS_READ             = 10
	STATE_RESET_STRING          = 11
)

type SandboxString struct {
	Len           int
	Pos           int
	Base          string
	BaseStack     []string
	Token         string
	TokenStack    []byte
	OutputStrings []string
}
