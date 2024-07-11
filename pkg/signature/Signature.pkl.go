// Code generated from Pkl module `io.blacktop.Symbolicator`. DO NOT EDIT.
package signature

type Signature struct {
	// The number of args.
	Args uint16 `pkl:"args"`

	// The string in function.
	Pattern string `pkl:"pattern"`

	// The name of the function this signature matches.
	Symbol string `pkl:"symbol"`

	// The name of the function that calls this function.
	Caller string `pkl:"caller"`
}
