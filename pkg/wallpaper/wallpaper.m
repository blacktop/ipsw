#import <Foundation/Foundation.h>
#import <CoreGraphics/CoreGraphics.h>
#import <AppKit/AppKit.h>
#import <QuartzCore/QuartzCore.h>
#import <objc/runtime.h>
#include "wallpaper.h"

// Helper function to set error
static void setError(wallpaper_error_t* error, const char* message, int code) {
    if (error) {
        if (message) {
            size_t len = strlen(message) + 1;
            error->message = (char*)malloc(len);
            if (error->message) {
                strncpy(error->message, message, len);
            }
        } else {
            error->message = NULL;
        }
        error->code = code;
    }
}

// Helper function to get CAPackage class
static Class GetCAPackageClass(void) {
    static Class packageClass = nil;
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        NSBundle *bundle = [NSBundle bundleWithPath:@"/System/Library/Frameworks/QuartzCore.framework"];
        if ([bundle load]) {
            packageClass = NSClassFromString(@"CAPackage");
        }
    });
    return packageClass;
}

// Helper function to create CAPackage
static id CreateCAPackage(NSURL *url, NSError **error) {
    Class packageClass = GetCAPackageClass();
    if (!packageClass) {
        return nil;
    }
    
    SEL selector = NSSelectorFromString(@"initWithContentsOfURL:type:options:error:");
    if (![packageClass instancesRespondToSelector:selector]) {
        return nil;
    }
    
    id package = [[packageClass alloc] init];
    if (!package) {
        return nil;
    }
    
    NSString *type = @"com.apple.caml";
    NSDictionary *options = @{};
    
    NSMethodSignature *signature = [packageClass instanceMethodSignatureForSelector:selector];
    NSInvocation *invocation = [NSInvocation invocationWithMethodSignature:signature];
    [invocation setTarget:package];
    [invocation setSelector:selector];
    [invocation setArgument:&url atIndex:2];
    [invocation setArgument:&type atIndex:3];
    [invocation setArgument:&options atIndex:4];
    [invocation setArgument:&error atIndex:5];
    [invocation invoke];
    
    return package;
}

// Implementation of parsing functions
unsigned char* parse_caml_wallpaper(const char* path, size_t* outSize, wallpaper_error_t* error) {
    *outSize = 0;
    
    if (!path) {
        setError(error, "Invalid path provided", 1);
        return NULL;
    }
    
    NSString *camlPath = [NSString stringWithUTF8String:path];
    NSURL *fileURL = [NSURL fileURLWithPath:camlPath];
    
    NSError *nsError = nil;
    id package = CreateCAPackage(fileURL, &nsError);
    
    if (!package || nsError) {
        NSString *errMsg = [NSString stringWithFormat:@"Error loading CAPackage: %@", nsError.localizedDescription];
        setError(error, [errMsg UTF8String], 3);
        return NULL;
    }
    
    // Extract basic package info using KVC since info is a property
    NSDictionary *info = [package valueForKey:@"info"];
    if (!info) {
        setError(error, "No package info found", 4);
        return NULL;
    }
    
    // Convert package info to JSON for Go consumption
    NSError *jsonError = nil;
    NSData *jsonData = [NSJSONSerialization dataWithJSONObject:info 
                                                      options:NSJSONWritingPrettyPrinted 
                                                        error:&jsonError];
    if (!jsonData || jsonError) {
        NSString *errMsg = [NSString stringWithFormat:@"Error serializing package info: %@", jsonError.localizedDescription];
        setError(error, [errMsg UTF8String], 5);
        return NULL;
    }
    
    // Create a buffer to return to Go
    *outSize = [jsonData length];
    unsigned char *buffer = malloc(*outSize);
    if (!buffer) {
        setError(error, "Memory allocation failed", 6);
        return NULL;
    }
    
    memcpy(buffer, [jsonData bytes], *outSize);
    return buffer;
}

char** extract_caml_images(const char* path, const char* outputDir, int* numImages, wallpaper_error_t* error) {
    *numImages = 0;
    
    if (!path || !outputDir) {
        setError(error, "Invalid path or output directory", 1);
        return NULL;
    }
    
    NSString *camlPath = [NSString stringWithUTF8String:path];
    NSString *outputPath = [NSString stringWithUTF8String:outputDir];
    NSURL *fileURL = [NSURL fileURLWithPath:camlPath];
    
    // Create output directory if it doesn't exist
    NSFileManager *fileManager = [NSFileManager defaultManager];
    if (![fileManager fileExistsAtPath:outputPath]) {
        NSError *dirError = nil;
        [fileManager createDirectoryAtPath:outputPath 
              withIntermediateDirectories:YES 
                               attributes:nil 
                                    error:&dirError];
        if (dirError) {
            NSString *errMsg = [NSString stringWithFormat:@"Failed to create output directory: %@", dirError.localizedDescription];
            setError(error, [errMsg UTF8String], 3);
            return NULL;
        }
    }
    
    // Load the CAPackage
    NSError *pkgError = nil;
    id package = CreateCAPackage(fileURL, &pkgError);
    
    if (!package || pkgError) {
        NSString *errMsg = [NSString stringWithFormat:@"Error loading CAPackage: %@", pkgError.localizedDescription];
        setError(error, [errMsg UTF8String], 4);
        return NULL;
    }
    
    // Get all the available images from the package using KVC
    NSDictionary *info = [package valueForKey:@"info"];
    NSArray *assets = info[@"assets"];
    
    if (!assets || ![assets isKindOfClass:[NSArray class]] || [assets count] == 0) {
        setError(error, "No assets found in package", 5);
        return NULL;
    }
    
    NSMutableArray *extractedPaths = [NSMutableArray array];
    
    // Process each asset and extract its image data
    for (NSDictionary *asset in assets) {
        NSString *assetName = asset[@"name"];
        if (!assetName) continue;
        
        // Get the image from the package using KVC
        id imageData = [package valueForKeyPath:[NSString stringWithFormat:@"objects.%@", assetName]];
        if (!imageData) continue;
        
        // This handles different types of image data that might be in the package
        NSImage *image = nil;
        if ([imageData isKindOfClass:[NSImage class]]) {
            image = (NSImage *)imageData;
        } else if ([imageData isKindOfClass:[NSData class]]) {
            image = [[NSImage alloc] initWithData:(NSData *)imageData];
        } else {
            continue;
        }
        
        if (!image) continue;
        
        // Save the image to the output directory
        NSString *outputFile = [outputPath stringByAppendingPathComponent:
                              [NSString stringWithFormat:@"%@.png", assetName]];
        NSData *pngData = [image TIFFRepresentation];
        NSBitmapImageRep *imageRep = [NSBitmapImageRep imageRepWithData:pngData];
        NSData *finalPngData = [imageRep representationUsingType:NSBitmapImageFileTypePNG properties:@{}];
        
        if (![finalPngData writeToFile:outputFile atomically:YES]) {
            NSString *errMsg = [NSString stringWithFormat:@"Failed to write image: %@", outputFile];
            setError(error, [errMsg UTF8String], 6);
            return NULL;
        }
        [extractedPaths addObject:outputFile];
    }
    
    // Prepare the return value as a C array of strings
    *numImages = (int)[extractedPaths count];
    if (*numImages == 0) {
        setError(error, "No images were successfully extracted", 7);
        return NULL;
    }
    
    char **result = malloc(*numImages * sizeof(char*));
    if (!result) {
        setError(error, "Memory allocation failed", 8);
        *numImages = 0;
        return NULL;
    }
    
    for (int i = 0; i < *numImages; i++) {
        NSString *path = extractedPaths[i];
        const char *cStr = [path UTF8String];
        size_t len = strlen(cStr) + 1;
        result[i] = malloc(len);
        if (!result[i]) {
            // Handle allocation failure - free everything we've allocated so far
            for (int j = 0; j < i; j++) {
                free(result[j]);
            }
            free(result);
            setError(error, "Memory allocation failed for path string", 9);
            *numImages = 0;
            return NULL;
        }
        memcpy(result[i], cStr, len);
    }
    
    return result;
}