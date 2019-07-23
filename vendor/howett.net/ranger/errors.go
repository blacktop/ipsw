package ranger

import "errors"

var (
	// ErrResourceChanged is the error returned by Read when the underlying resource's integrity can no longer be verified.
	// In the case of HTTP, this usually happens when the remote document's validator has changed.
	ErrResourceChanged = errors.New("unsatisfiable range request; resource may have changed")

	// ErrResourceNotFound is returned by the first Read operation that determines that a resource is inaccessible.
	ErrResourceNotFound = errors.New("resource not found")
)
