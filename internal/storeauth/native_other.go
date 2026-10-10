//go:build !darwin || ios || !cgo

package storeauth

import "time"

func nativeSupported() bool { return false }

func nativeHeaderData() ([]byte, error) { return nil, ErrNativeUnavailable }

func nativeSign([]byte, time.Duration) ([]byte, error) { return nil, ErrNativeUnavailable }

func openNativeSAP() (sapNative, error) { return nil, ErrNativeUnavailable }
