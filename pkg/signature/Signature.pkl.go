// Code generated from Pkl module `io.blacktop.Symbolicator`. DO NOT EDIT.
package signature

type Signature struct {
	// The number of args.
	Args uint16 `pkl:"args"`

	// The unique anchors in function.
	Anchors []*Anchor `pkl:"anchors"`

	// The name of the function this signature matches.
	Symbol string `pkl:"symbol"`

	// The function prototype.
	Prototype string `pkl:"prototype"`

	// The name of the function that calls this function.
	Caller string `pkl:"caller"`
}
