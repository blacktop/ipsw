//go:build ipsw_fp && cgo && (darwin || linux)

package fairplay

/*
#cgo LDFLAGS: -lipsw_fp
#cgo darwin LDFLAGS: -framework Security -framework CoreFoundation -framework IOKit -framework Foundation -lobjc
#cgo linux LDFLAGS: -ldl -lpthread -lm
#include <stdlib.h>
#include "ipsw_fp.h"
*/
import "C"

import "unsafe"

func offlineAvailable() error {
	if C.ipsw_fp_abi_version() != 1 || C.ipsw_fp_auth_capacity() != C.size_t(AuthorizationMaxBytes) {
		return ErrOfflineABI
	}
	return nil
}

// Paths are copied into bounded C-owned allocations so no Go memory is retained
// across the call. The ABI borrows the initialized spans only for its duration.
func offlinePath(path string) unsafe.Pointer {
	pointer := C.malloc(C.size_t(len(path)))
	if pointer != nil {
		copy(unsafe.Slice((*byte)(pointer), len(path)), path)
	}
	return pointer
}

func offlineDecrypt(ipa, authorization, output string) (Result, error) {
	if err := offlineAvailable(); err != nil {
		return Result{}, err
	}
	var paths [3]unsafe.Pointer
	for i, path := range [3]string{ipa, authorization, output} {
		if paths[i] = offlinePath(path); paths[i] == nil {
			return Result{}, ErrOfflineProcessing
		}
		defer C.free(paths[i])
	}
	var flags C.uint32_t
	status := C.ipsw_fp_decrypt_v1(
		(*C.uint8_t)(paths[0]), C.size_t(len(ipa)),
		(*C.uint8_t)(paths[1]), C.size_t(len(authorization)),
		(*C.uint8_t)(paths[2]), C.size_t(len(output)), &flags,
	)
	if err := offlineStatus(int32(status)); err != nil {
		return Result{}, err
	}
	if flags&^parentSyncUnconfirmed != 0 {
		return Result{}, ErrOfflineABI
	}
	return Result{ParentSyncUnconfirmed: flags&parentSyncUnconfirmed != 0}, nil
}

func offlineCapture() ([]byte, error) {
	if err := offlineAvailable(); err != nil {
		return nil, err
	}
	buffer := C.malloc(C.size_t(AuthorizationMaxBytes))
	if buffer == nil {
		return nil, ErrOfflineProcessing
	}
	defer C.free(buffer)
	defer clear(unsafe.Slice((*byte)(buffer), AuthorizationMaxBytes))
	var written C.size_t
	status := C.ipsw_fp_capture_auth_v1((*C.uint8_t)(buffer), C.size_t(AuthorizationMaxBytes), &written)
	if err := offlineStatus(int32(status)); err != nil {
		return nil, err
	}
	if written == 0 || written > C.size_t(AuthorizationMaxBytes) {
		return nil, ErrOfflineABI
	}
	payload := C.GoBytes(buffer, C.int(written))
	if !ValidAuthorization(payload) {
		clear(payload)
		return nil, ErrOfflineABI
	}
	return payload, nil
}
