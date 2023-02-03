//go:build darwin && cgo && objc

/*
objc impiments the Objective-C runtime API for Go.
*/
package objc

// #cgo CFLAGS: -W -Wall -Wno-unused-parameter -Wno-unused-function -O3
// #cgo LDFLAGS: -lobjc
import "C"
