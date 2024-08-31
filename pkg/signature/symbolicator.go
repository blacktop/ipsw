package signature

type Anchor struct {
	// The unique string.
	String string `json:"string"`

	// The segment the string is in.
	Segment string `json:"segment"`

	// The section the string is in.
	Section string `json:"section"`

	// The name of the function that uses this anchor as an argument.
	Caller string `json:"caller,omitempty" jsonschema:"oneof_type=string;null"`
}

type Signature struct {
	// The number of args.
	Args uint16 `json:"args"`

	// The unique anchors in function.
	Anchors []Anchor `json:"anchors"`

	// The name of the function this signature matches.
	Symbol string `json:"symbol"`

	// The function prototype.
	Prototype string `json:"prototype"`

	// The backtrace of single xref functions that call this function.
	Backtrace []string `json:"backtrace,omitempty"`
}

type Version struct {
	// The maximum version supported.
	Max string `json:"max"`

	// The minimum version supported.
	Min string `json:"min"`
}

type Symbolicator struct {
	// The target for the signatures.
	Target string `json:"target"`

	// The total number of possible symbol matches.
	Total uint `json:"total"`

	// The version of the signatures.
	Version Version `json:"version"`

	// The signatures.
	Signatures []Signature `json:"signatures"`
}
