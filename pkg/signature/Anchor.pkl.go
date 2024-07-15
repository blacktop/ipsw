// Code generated from Pkl module `io.blacktop.Symbolicator`. DO NOT EDIT.
package signature

type Anchor struct {
	// The unique string.
	String string `pkl:"string"`

	// The segment the string is in.
	Segment string `pkl:"segment"`

	// The section the string is in.
	Section string `pkl:"section"`

	// The name of the function that uses this as an argument.
	Caller string `pkl:"caller"`
}
