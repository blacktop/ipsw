package kernelcache

import (
	"errors"
	"testing"

	"github.com/blacktop/ipsw/pkg/img4"
)

func TestParseImg4DataRejectsEncryptedKernelcache(t *testing.T) {
	payload, err := img4.CreatePayload(&img4.CreatePayloadConfig{
		Type:        img4.IM4P_KERNELCACHE,
		Version:     "KernelCacheBuilder-test",
		Data:        []byte("encrypted kernel payload"),
		Compression: "none",
		Keybags: []img4.Keybag{
			{
				IV:  []byte("1234567890abcdef"),
				Key: []byte("1234567890abcdef1234567890abcdef"),
			},
		},
	})
	if err != nil {
		t.Fatalf("CreatePayload() error = %v", err)
	}

	data, err := payload.Marshal()
	if err != nil {
		t.Fatalf("Marshal() error = %v", err)
	}

	_, err = ParseImg4Data(data)
	if !errors.Is(err, ErrEncryptedKernelCache) {
		t.Fatalf("ParseImg4Data() error = %v, want %v", err, ErrEncryptedKernelCache)
	}
}
