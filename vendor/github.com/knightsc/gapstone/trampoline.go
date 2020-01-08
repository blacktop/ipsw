/*
Gapstone is a Go binding for the Capstone disassembly library. For examples,
try reading the *_test.go files.

	Library Author: Nguyen Anh Quynh
	Binding Author: Ben Nagy
	License: BSD style - see LICENSE file for details
    (c) 2013 COSEINC. All Rights Reserved.
*/

package gapstone

// #cgo LDFLAGS: -lcapstone
// #cgo freebsd CFLAGS: -I/usr/local/include
// #cgo freebsd LDFLAGS: -L/usr/local/lib
// #include <stdlib.h>
// #include <capstone/capstone.h>
import "C"

import (
	"reflect"
	"unsafe"
)

// Because of a chicken and egg problem, this needs to be in a different file than
// where it is used (engine.go), see https://github.com/golang/go/issues/9294.
//export trampoline
func trampoline(buffer *C.uint8_t, buflen C.size_t, offset C.size_t, user_data unsafe.Pointer) C.size_t {
	/*
	   This is all a little confusing. Basically the callback system works as follows:
	     - forward declaration above: extern size_t trampoline(...
	     - export this Go function so it is visible to C
	     - register this (and only this) trampoline as the capstone C callback
	     - use the capstone user_data opaque pointer to pass a wrapped struct. That
	       struct contains both the Go level UserData and the Go user callback
	       function
	     - When this function is invoked by capstone, we create the Go args,
	       unwrap the end-user's callback and then invoke it and return the
	       result to C
	*/

	// convert buffer to a []byte. This provides memory safety, so we don't
	// need to pass the buflen param to the Go end-user
	var data []byte
	sh := (*reflect.SliceHeader)(unsafe.Pointer(&data))
	sh.Data = uintptr(unsafe.Pointer(buffer))
	sh.Len = int(buflen)
	sh.Cap = int(buflen)

	// Unwrap the Callback and UserData struct ( ud can be nil )
	cbw := (*cbWrapper)(user_data)
	return (C.size_t)(cbw.fn(data, int(offset), cbw.ud))
}
