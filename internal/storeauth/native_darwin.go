//go:build darwin && !ios && cgo

package storeauth

/*
#cgo LDFLAGS: -framework Foundation -framework IOKit -framework CoreFoundation
#include "native_darwin.h"
*/
import "C"

import (
	"errors"
	"runtime"
	"time"
	"unsafe"
)

func nativeSupported() bool {
	return C.ipsw_native_supported() != 0
}

func nativeHeaderData() ([]byte, error) {
	result := C.ipsw_native_headers()
	return consumeNativeResult(result, "headers", maxNativeHeadersBytes)
}

func nativeSign(body []byte, wait time.Duration) ([]byte, error) {
	result := C.ipsw_native_sign(unsafe.Pointer(unsafe.SliceData(body)), C.size_t(len(body)), C.double(wait.Seconds()))
	runtime.KeepAlive(body)
	return consumeNativeResult(result, "signing", maxNativeSignatureBytes)
}

type nativeSAP struct{ handle unsafe.Pointer }

func openNativeSAP() (sapNative, error) {
	var result C.ipsw_native_result
	handle := C.ipsw_sap_open(&result)
	if err := nativeResultError(result, "SAP initialization"); err != nil {
		return nil, err
	}
	if handle == nil {
		return nil, errors.New("native SAP initialization returned no session")
	}
	return &nativeSAP{handle: handle}, nil
}

func (s *nativeSAP) handshake(body []byte) ([]byte, error) {
	result := C.ipsw_sap_handshake(s.handle, unsafe.Pointer(unsafe.SliceData(body)), C.size_t(len(body)))
	runtime.KeepAlive(body)
	return consumeNativeResult(result, "SAP handshake", maxSAPResponse)
}

func (s *nativeSAP) complete(body []byte) error {
	result := C.ipsw_sap_complete(s.handle, unsafe.Pointer(unsafe.SliceData(body)), C.size_t(len(body)))
	runtime.KeepAlive(body)
	defer C.ipsw_native_result_free(&result)
	return nativeResultError(result, "SAP completion")
}

func (s *nativeSAP) sign(body []byte) ([]byte, error) {
	result := C.ipsw_sap_sign(s.handle, unsafe.Pointer(unsafe.SliceData(body)), C.size_t(len(body)))
	runtime.KeepAlive(body)
	return consumeNativeResult(result, "SAP signing", maxNativeSignatureBytes)
}

func (s *nativeSAP) close() {
	C.ipsw_sap_close(s.handle)
	s.handle = nil
}

func nativeResultError(result C.ipsw_native_result, operation string) error {
	if result.status == C.IPSW_NATIVE_UNAVAILABLE {
		return ErrNativeUnavailable
	}
	if result.status != C.IPSW_NATIVE_OK {
		return nativeFailure(operation, C.GoString(&result.error_domain[0]), int64(result.error_code))
	}
	return nil
}

func consumeNativeResult(result C.ipsw_native_result, operation string, maxLength int) ([]byte, error) {
	defer C.ipsw_native_result_free(&result)
	if err := nativeResultError(result, operation); err != nil {
		return nil, err
	}
	if result.bytes == nil || result.length == 0 || uint64(result.length) > uint64(maxLength) {
		return nil, errors.New("native App Store authentication returned an invalid result")
	}
	return C.GoBytes(unsafe.Pointer(result.bytes), C.int(result.length)), nil
}
