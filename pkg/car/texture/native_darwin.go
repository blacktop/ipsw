//go:build darwin && cgo

package texture

/*
#cgo LDFLAGS: -framework CoreFoundation -framework CoreGraphics -framework ImageIO
#include <CoreFoundation/CoreFoundation.h>
#include <CoreGraphics/CoreGraphics.h>
#include <ImageIO/ImageIO.h>
#include <stdint.h>
#include <string.h>

static int car_decode_texture(const uint8_t *src, size_t size, uint8_t *dst, size_t width, size_t height) {
	CFDataRef data = CFDataCreate(kCFAllocatorDefault, src, (CFIndex)size);
	if (!data) return 1;
	CGImageSourceRef source = CGImageSourceCreateWithData(data, NULL);
	CFRelease(data);
	if (!source) return 2;
	CGImageRef image = NULL;
	if (CGImageSourceGetCount(source) == 1) image = CGImageSourceCreateImageAtIndex(source, 0, NULL);
	CFRelease(source);
	if (!image) return 3;
	int result = 4;
	if (CGImageGetWidth(image) == width && CGImageGetHeight(image) == height &&
		CGImageGetBitsPerComponent(image) == 8 && CGImageGetBitsPerPixel(image) == 32 &&
		CGImageGetAlphaInfo(image) == kCGImageAlphaLast &&
		(CGImageGetBitmapInfo(image) & kCGBitmapByteOrderMask) == kCGBitmapByteOrderDefault) {
		size_t stride = CGImageGetBytesPerRow(image);
		CFDataRef pixels = CGDataProviderCopyData(CGImageGetDataProvider(image));
		if (pixels && stride >= width * 4 && stride <= SIZE_MAX / height &&
			(size_t)CFDataGetLength(pixels) >= stride * height) {
			const uint8_t *bytes = CFDataGetBytePtr(pixels);
			for (size_t y = 0; y < height; y++) memcpy(dst + y * width * 4, bytes + y * stride, width * 4);
			result = 0;
		}
		if (pixels) CFRelease(pixels);
	}
	CGImageRelease(image);
	return result;
}
*/
import "C"

import (
	"fmt"
	"image"
	"unsafe"

	"github.com/blacktop/ipsw/pkg/car/internal/pixel"
)

func decodeNativeTexture(data []byte, width, height int) (*image.RGBA, error) {
	if len(data) == 0 || len(data) > pixel.MaxBytes {
		return nil, fmt.Errorf("invalid native texture input size")
	}
	if _, _, err := pixel.Layout(width, height, 4, 0); err != nil {
		return nil, err
	}
	img := image.NewRGBA(image.Rect(0, 0, width, height))
	// Both buffers contain only bytes and remain alive for this synchronous call.
	// ImageIO receives a CFData copy, and no Go pointer is retained by C.
	status := C.car_decode_texture((*C.uint8_t)(unsafe.Pointer(&data[0])), C.size_t(len(data)), (*C.uint8_t)(unsafe.Pointer(&img.Pix[0])), C.size_t(width), C.size_t(height))
	if status != 0 {
		return nil, fmt.Errorf("ImageIO cannot decode this texture as RGBA8 (status %d)", status)
	}
	return img, nil
}
