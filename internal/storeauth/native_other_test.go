//go:build !darwin || ios || !cgo

package storeauth

import (
	"context"
	"errors"
	"testing"
)

func TestNativeUnavailable(t *testing.T) {
	if NativeSupported() {
		t.Fatal("native authentication is unexpectedly available")
	}
	if _, err := NativeHeaders(context.Background()); !errors.Is(err, ErrNativeUnavailable) {
		t.Fatalf("NativeHeaders error = %v", err)
	}
	if _, err := Sign(context.Background(), []byte("synthetic request")); !errors.Is(err, ErrNativeUnavailable) {
		t.Fatalf("Sign error = %v", err)
	}
}
