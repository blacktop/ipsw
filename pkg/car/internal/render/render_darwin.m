//go:build darwin && cgo

#import <AppKit/AppKit.h>
#import <ImageIO/ImageIO.h>
#include <math.h>
#include "render_darwin.h"

struct ipsw_car_render {
    CFDataRef data;
    CGImageSourceRef image;
    CGPDFDocumentRef document;
    NSImage *svg;
    size_t index;
    size_t limit;
    double width;
    double height;
};

void ipsw_car_render_close(ipsw_car_render *source) {
    if (!source) return;
    if (source->image) CFRelease(source->image);
    if (source->document) CGPDFDocumentRelease(source->document);
    [source->svg release];
    if (source->data) CFRelease(source->data);
    free(source);
}

// Allow for up to eight decoded bytes per source pixel before asking a native
// codec to allocate. The output bitmap has a separate four-byte pixel bound.
static bool valid_size(double width, double height, size_t limit) {
    return isfinite(width) && isfinite(height) && width > 0 && height > 0 &&
           ceil(width) <= limit / 8 && ceil(height) <= limit / 8 / ceil(width);
}

static bool read_dimension(CFDictionaryRef properties, CFStringRef key, double *value) {
    CFTypeRef number = CFDictionaryGetValue(properties, key);
    return number && CFGetTypeID(number) == CFNumberGetTypeID() &&
           CFNumberGetValue(number, kCFNumberDoubleType, value);
}

static const char *open_source(ipsw_car_render *source, int kind, size_t *width, size_t *height) {
    double w = 0, h = 0;
    if (kind == 1) {
        const void *keys[] = {kCGImageSourceShouldCache};
        const void *values[] = {kCFBooleanFalse};
        CFDictionaryRef options = CFDictionaryCreate(NULL, keys, values, 1,
            &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
        if (!options) return "cannot allocate image source options";
        source->image = CGImageSourceCreateWithData(source->data, options);
        CFRelease(options);
        if (!source->image) return "invalid HEIF source";
        CFStringRef type = CGImageSourceGetType(source->image);
        if (!type || (!CFEqual(type, CFSTR("public.heic")) && !CFEqual(type, CFSTR("public.heif")) &&
                      !CFEqual(type, CFSTR("public.heics")) && !CFEqual(type, CFSTR("public.heifs"))))
            return "payload is not a HEIF image";
        source->index = CGImageSourceGetPrimaryImageIndex(source->image);
        if (source->index >= CGImageSourceGetCount(source->image)) return "HEIF primary image is missing";
        CFDictionaryRef props = CGImageSourceCopyPropertiesAtIndex(source->image, source->index, NULL);
        if (!props) return "HEIF dimensions are missing";
        bool found = read_dimension(props, kCGImagePropertyPixelWidth, &w) &&
                     read_dimension(props, kCGImagePropertyPixelHeight, &h);
        CFRelease(props);
        if (!found) return "HEIF dimensions are missing";
    } else if (kind == 2) {
        CGDataProviderRef provider = CGDataProviderCreateWithCFData(source->data);
        if (!provider) return "cannot create PDF provider";
        source->document = CGPDFDocumentCreateWithProvider(provider);
        CGDataProviderRelease(provider);
        if (!source->document || !CGPDFDocumentIsUnlocked(source->document)) return "invalid or locked PDF";
        CGPDFPageRef page = CGPDFDocumentGetPage(source->document, 1);
        if (!page) return "PDF has no page";
        CGRect box = CGRectIntersection(CGPDFPageGetBoxRect(page, kCGPDFCropBox),
                                        CGPDFPageGetBoxRect(page, kCGPDFMediaBox));
        w = box.size.width;
        h = box.size.height;
        int rotation = CGPDFPageGetRotationAngle(page) % 180;
        if (rotation == 90 || rotation == -90) {
            double swap = w; w = h; h = swap;
        }
    } else if (kind == 3) {
        source->svg = [[NSImage alloc] initWithData:(NSData *)source->data];
        if (!source->svg) return "SVG is unsupported by this version of macOS";
        NSSize size = [source->svg size];
        w = size.width;
        h = size.height;
    } else {
        return "unknown render format";
    }
    if (!valid_size(w, h, source->limit)) return "invalid or excessive source dimensions";
    source->width = w;
    source->height = h;
    *width = (size_t)ceil(w);
    *height = (size_t)ceil(h);
    return NULL;
}

const char *ipsw_car_render_open(const unsigned char *data, size_t length, int kind,
                               size_t limit, ipsw_car_render **result,
                               size_t *width, size_t *height) {
    *result = NULL;
    if (!data || !length || length > limit) return "invalid source size";
    ipsw_car_render *source = calloc(1, sizeof(*source));
    if (!source) return "cannot allocate render source";
    source->limit = limit;
    source->data = CFDataCreate(NULL, data, (CFIndex)length);
    if (!source->data) {
        ipsw_car_render_close(source);
        return "cannot allocate source data";
    }
    const char *error = NULL;
    @autoreleasepool {
        @try {
            error = open_source(source, kind, width, height);
        } @catch (NSException *exception) {
            error = "native image reader rejected the source";
        }
    }
    if (error) {
        ipsw_car_render_close(source);
        return error;
    }
    *result = source;
    return NULL;
}

const char *ipsw_car_render_draw(ipsw_car_render *source, size_t width, size_t height,
                               unsigned char *pixels, size_t length) {
    if (!source || !pixels || !width || width > source->limit / 4 ||
        !height || height > source->limit / 4 / width || length != width * height * 4)
        return "invalid output bitmap size";
    CGColorSpaceRef space = CGColorSpaceCreateWithName(kCGColorSpaceSRGB);
    if (!space) return "cannot create sRGB color space";
    CGContextRef context = CGBitmapContextCreate(pixels, width, height, 8, width * 4, space,
        kCGImageAlphaPremultipliedLast | kCGBitmapByteOrder32Big);
    CGColorSpaceRelease(space);
    if (!context) return "cannot allocate output context";
    const char *error = NULL;
    CGImageRef image = NULL;
    @autoreleasepool {
        @try {
            CGRect rect = CGRectMake(0, 0, width, height);
            if (source->document) {
                CGPDFPageRef page = CGPDFDocumentGetPage(source->document, 1);
                // CGPDFPageGetDrawingTransform only scales down. Apply the
                // requested scale separately so vector previews also upscale.
                double scale = fmin(width / source->width, height / source->height);
                CGContextTranslateCTM(context, (width - source->width * scale) / 2,
                                      (height - source->height * scale) / 2);
                CGContextScaleCTM(context, scale, scale);
                CGRect pageRect = CGRectMake(0, 0, source->width, source->height);
                CGContextConcatCTM(context, CGPDFPageGetDrawingTransform(page, kCGPDFCropBox, pageRect, 0, true));
                CGContextDrawPDFPage(context, page);
            } else {
                if (source->image) {
                    image = CGImageSourceCreateImageAtIndex(source->image, source->index, NULL);
                } else {
                    NSRect proposed = NSMakeRect(0, 0, width, height);
                    CGImageRef proposedImage = [source->svg CGImageForProposedRect:&proposed context:nil hints:nil];
                    if (proposedImage) image = CGImageRetain(proposedImage);
                }
                if (!image) {
                    error = "native decoder produced no image";
                } else if (!valid_size(CGImageGetWidth(image), CGImageGetHeight(image), source->limit)) {
                    error = "decoded dimensions exceed limit";
                } else {
                    CGContextSetBlendMode(context, kCGBlendModeCopy);
                    CGContextDrawImage(context, rect, image);
                }
            }
        } @catch (NSException *exception) {
            error = "native renderer rejected the image";
        }
    }
    if (image) CGImageRelease(image);
    CGContextRelease(context);
    return error;
}
