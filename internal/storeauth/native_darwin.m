//go:build darwin && !ios && cgo

#import <Foundation/Foundation.h>
#import <IOKit/IOKitLib.h>
#include <dlfcn.h>
#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include <sys/sysctl.h>
#include <time.h>

#include "native_darwin.h"

@interface NSObject (IPSWNativeStoreAuth)
+ (id)retrieveOTPHeadersForDSID:(NSString *)dsid;
+ (id)currentDevice;
+ (id)machineSerialNumber;
+ (id)defaultSession;
- (id)localUserUUID;
- (id)serverFriendlyDescription;
- (id)uniqueDeviceIdentifier;
- (id)locale;
- (id)signData:(NSData *)data bag:(id)bag;
- (id)resultWithTimeout:(NSTimeInterval)timeout error:(NSError **)error;
- (NSData *)handshakeRequestWithCertificateData:(NSData *)data error:(NSError **)error;
- (BOOL)completeWithHandshakeResponse:(NSData *)data error:(NSError **)error;
- (NSData *)signData:(NSData *)data error:(NSError **)error;
- (void)invalidate;
@end

enum {
    IPSW_NATIVE_MAX_HEADERS = 32 * 1024,
    IPSW_NATIVE_MAX_SIGNATURE = 64 * 1024,
    IPSW_NATIVE_MAX_BODY = 4 * 1024 * 1024,
    IPSW_SAP_MAX_SETUP = 1024 * 1024
};

static pthread_once_t framework_once = PTHREAD_ONCE_INIT;
static void *framework_handles[4];
static pthread_once_t osprey_once = PTHREAD_ONCE_INIT;
static void *osprey_handle;

static void load_osprey(void) {
    osprey_handle = dlopen("/System/Library/PrivateFrameworks/Osprey.framework/Osprey", RTLD_NOW | RTLD_LOCAL);
}

static void load_frameworks(void) {
    // Objective-C classes and framework-owned singleton objects may survive any
    // individual request. Keep exactly one reference per framework for the
    // process lifetime instead of repeatedly incrementing dlopen references.
    framework_handles[0] = dlopen("/System/Library/PrivateFrameworks/AOSKit.framework/AOSKit", RTLD_NOW);
    framework_handles[1] = dlopen("/System/Library/PrivateFrameworks/AuthKit.framework/AuthKit", RTLD_NOW);
    framework_handles[2] = dlopen("/System/Library/PrivateFrameworks/AppleMediaServices.framework/AppleMediaServices", RTLD_NOW);
    // IMURLBag is registered by IMFoundation, which PodcastsFoundation loads.
    framework_handles[3] = dlopen("/System/Library/PrivateFrameworks/PodcastsFoundation.framework/PodcastsFoundation", RTLD_NOW);
}

static ipsw_native_result failed(int status) {
    ipsw_native_result result = {0};
    result.status = status;
    return result;
}

static ipsw_native_result failed_with_error(NSError *error) {
    ipsw_native_result result = failed(IPSW_NATIVE_FAILED);
    if (!error) {
        return result;
    }
    result.error_code = (int64_t)[error code];
    const char *domain = [[error domain] UTF8String];
    if (!domain) {
        return result;
    }
    size_t length = strnlen(domain, sizeof(result.error_domain));
    if (length == 0 || length >= sizeof(result.error_domain)) {
        return result;
    }
    for (size_t index = 0; index < length; index++) {
        char value = domain[index];
        if (!((value >= 'a' && value <= 'z') || (value >= 'A' && value <= 'Z') ||
              (value >= '0' && value <= '9') || value == '.' || value == '_' || value == '-')) {
            return result;
        }
    }
    memcpy(result.error_domain, domain, length);
    return result;
}

static ipsw_native_result copied_data(NSData *data, size_t maximum) {
    if (![data isKindOfClass:[NSData class]]) {
        return failed(IPSW_NATIVE_FAILED);
    }
    NSUInteger length = [data length];
    if (length == 0 || length > maximum) {
        return failed(IPSW_NATIVE_FAILED);
    }
    ipsw_native_result result = {0};
    result.bytes = malloc(length);
    if (!result.bytes) {
        return failed(IPSW_NATIVE_FAILED);
    }
    result.length = length;
    // AMS returns a Swift-backed NSData subclass. This accessor also works for
    // subclasses whose -bytes method uses a different runtime type encoding.
    @try {
        [data getBytes:result.bytes length:length];
    } @catch (NSException *exception) {
        (void)exception;
        ipsw_native_result_free(&result);
        return failed(IPSW_NATIVE_FAILED);
    }
    return result;
}

static NSString *nonempty_string(id object) {
    if (![object isKindOfClass:[NSString class]] || [(NSString *)object length] == 0) {
        return nil;
    }
    return object;
}

static NSString *platform_string(NSString *key) {
    io_service_t service = IOServiceGetMatchingService(kIOMainPortDefault, IOServiceMatching("IOPlatformExpertDevice"));
    if (!service) {
        return nil;
    }
    CFTypeRef property = IORegistryEntryCreateCFProperty(service, (CFStringRef)key, kCFAllocatorDefault, 0);
    IOObjectRelease(service);
    if (!property) {
        return nil;
    }
    NSString *value = nil;
    if (CFGetTypeID(property) == CFStringGetTypeID()) {
        value = [(NSString *)property copy];
    }
    CFRelease(property);
    return [value autorelease];
}

static NSString *system_string(const char *name) {
    char value[256] = {0};
    size_t length = sizeof(value);
    if (sysctlbyname(name, value, &length, NULL, 0) != 0 || length == 0 || length > sizeof(value)) {
        return nil;
    }
    value[sizeof(value) - 1] = 0;
    return nonempty_string([NSString stringWithUTF8String:value]);
}

static NSString *fallback_client_info(void) {
    NSString *model = system_string("hw.model") ?: @"Mac";
    NSString *version = system_string("kern.osproductversion") ?: @"13.0";
    NSString *build = system_string("kern.osversion") ?: @"22A380";
    return [NSString stringWithFormat:@"<%@> <Mac OS X;%@;%@> <com.apple.AuthKit/1 (com.apple.akd/1.0)>", model, version, build];
}

static int headers_supported(void) {
    Class utilities = NSClassFromString(@"AOSUtilities");
    return framework_handles[0] && framework_handles[1] && utilities &&
        [utilities respondsToSelector:@selector(retrieveOTPHeadersForDSID:)];
}

static int signing_supported(void) {
    Class session = NSClassFromString(@"AMSMescalSession");
    Class bag = NSClassFromString(@"IMURLBag");
    return framework_handles[2] && session && bag &&
        [session respondsToSelector:@selector(defaultSession)] &&
        [session instancesRespondToSelector:@selector(signData:bag:)];
}

int ipsw_native_supported(void) {
    @autoreleasepool {
        @try {
            pthread_once(&framework_once, load_frameworks);
            return headers_supported() && signing_supported();
        } @catch (NSException *exception) {
            (void)exception;
            return 0;
        }
    }
}

ipsw_native_result ipsw_native_headers(void) {
    @autoreleasepool {
        @try {
            pthread_once(&framework_once, load_frameworks);
            if (!headers_supported()) {
                return failed(IPSW_NATIVE_UNAVAILABLE);
            }
            Class utilities = NSClassFromString(@"AOSUtilities");
            id otp = [utilities retrieveOTPHeadersForDSID:@"-2"];
            if (![otp isKindOfClass:[NSDictionary class]]) {
                return failed(IPSW_NATIVE_FAILED);
            }
            NSString *md = nonempty_string([otp objectForKey:@"X-Apple-MD"]);
            NSString *mdm = nonempty_string([otp objectForKey:@"X-Apple-MD-M"]);
            if (!md || !mdm) {
                return failed(IPSW_NATIVE_FAILED);
            }

            Class deviceClass = NSClassFromString(@"AKDevice");
            id device = [deviceClass respondsToSelector:@selector(currentDevice)] ? [deviceClass currentDevice] : nil;
            NSString *localUser = [device respondsToSelector:@selector(localUserUUID)] ? nonempty_string([device localUserUUID]) : nil;
            NSString *clientInfo = [device respondsToSelector:@selector(serverFriendlyDescription)] ? nonempty_string([device serverFriendlyDescription]) : nil;
            id locale = [device respondsToSelector:@selector(locale)] ? [device locale] : nil;
            NSString *localeName = [locale respondsToSelector:@selector(localeIdentifier)] ? nonempty_string([locale localeIdentifier]) : nil;

            NSString *deviceID = nonempty_string(platform_string(@"IOPlatformUUID"));
            if (!deviceID && [device respondsToSelector:@selector(uniqueDeviceIdentifier)]) {
                deviceID = nonempty_string([device uniqueDeviceIdentifier]);
            }
            if (!deviceID) {
                return failed(IPSW_NATIVE_FAILED);
            }
            NSString *serial = nonempty_string(platform_string(@"IOPlatformSerialNumber"));
            if (!serial && [utilities respondsToSelector:@selector(machineSerialNumber)]) {
                serial = nonempty_string([utilities machineSerialNumber]);
            }

            NSISO8601DateFormatter *formatter = [[[NSISO8601DateFormatter alloc] init] autorelease];
            [formatter setFormatOptions:NSISO8601DateFormatWithInternetDateTime];
            [formatter setTimeZone:[NSTimeZone timeZoneForSecondsFromGMT:0]];
            NSDictionary *headers = @{
                @"X-Apple-I-MD": md,
                @"X-Apple-I-MD-M": mdm,
                @"X-Apple-I-MD-RINFO": nonempty_string([otp objectForKey:@"X-Apple-MD-RINFO"]) ?: @"17106176",
                @"X-Apple-I-MD-LU": localUser ?: @"",
                @"X-Apple-I-Client-Time": [formatter stringFromDate:[NSDate date]],
                @"X-Apple-I-TimeZone": @"UTC",
                @"X-Apple-Locale": localeName ?: @"en_US",
                @"X-Mme-Device-Id": deviceID,
                @"X-Apple-I-SRL-NO": serial ?: @"0",
                @"X-MMe-Client-Info": clientInfo ?: fallback_client_info()
            };
            NSError *error = nil;
            NSData *data = [NSJSONSerialization dataWithJSONObject:headers options:0 error:&error];
            if (error) {
                return failed_with_error(error);
            }
            return copied_data(data, IPSW_NATIVE_MAX_HEADERS);
        } @catch (NSException *exception) {
            (void)exception;
            return failed(IPSW_NATIVE_FAILED);
        }
    }
}

ipsw_native_result ipsw_native_sign(const void *body, size_t length, double timeout) {
    @autoreleasepool {
        @try {
            if (length > IPSW_NATIVE_MAX_BODY || (!body && length != 0) || !(timeout > 0.0) || timeout > 20.0) {
                return failed(IPSW_NATIVE_FAILED);
            }
            struct timespec started;
            if (clock_gettime(CLOCK_MONOTONIC, &started) != 0) {
                return failed(IPSW_NATIVE_FAILED);
            }
            pthread_once(&framework_once, load_frameworks);
            if (!signing_supported()) {
                return failed(IPSW_NATIVE_UNAVAILABLE);
            }
            id session = [NSClassFromString(@"AMSMescalSession") defaultSession];
            id bag = [[[NSClassFromString(@"IMURLBag") alloc] init] autorelease];
            if (!session || !bag || ![session respondsToSelector:@selector(signData:bag:)]) {
                return failed(IPSW_NATIVE_FAILED);
            }
            NSData *data = [NSData dataWithBytes:body length:length];
            id promise = [session signData:data bag:bag];
            if (![promise respondsToSelector:@selector(resultWithTimeout:error:)]) {
                return failed(IPSW_NATIVE_FAILED);
            }
            struct timespec now;
            if (clock_gettime(CLOCK_MONOTONIC, &now) != 0) {
                return failed(IPSW_NATIVE_FAILED);
            }
            timeout -= (double)(now.tv_sec - started.tv_sec) + (double)(now.tv_nsec - started.tv_nsec) / 1000000000.0;
            if (!(timeout > 0.0)) {
                return failed(IPSW_NATIVE_FAILED);
            }
            NSError *error = nil;
            id signature = [promise resultWithTimeout:timeout error:&error];
            if (error) {
                return failed_with_error(error);
            }
            return copied_data(signature, IPSW_NATIVE_MAX_SIGNATURE);
        } @catch (NSException *exception) {
            (void)exception;
            return failed(IPSW_NATIVE_FAILED);
        }
    }
}

void *ipsw_sap_open(ipsw_native_result *error) {
    @autoreleasepool {
        *error = failed(IPSW_NATIVE_FAILED);
        @try {
            pthread_once(&osprey_once, load_osprey);
            Class cls = NSClassFromString(@"OspreyMescalSession");
            if (!osprey_handle || !cls ||
                ![cls instancesRespondToSelector:@selector(handshakeRequestWithCertificateData:error:)] ||
                ![cls instancesRespondToSelector:@selector(completeWithHandshakeResponse:error:)] ||
                ![cls instancesRespondToSelector:@selector(signData:error:)] ||
                ![cls instancesRespondToSelector:@selector(invalidate)]) {
                *error = failed(IPSW_NATIVE_UNAVAILABLE);
                return NULL;
            }
            // The retained native object is owned by Go until ipsw_sap_close.
            id session = [[cls alloc] init];
            if (!session) {
                return NULL;
            }
            *error = failed(IPSW_NATIVE_OK);
            return session;
        } @catch (NSException *exception) {
            (void)exception;
            return NULL;
        }
    }
}

ipsw_native_result ipsw_sap_handshake(void *session, const void *body, size_t length) {
    @autoreleasepool {
        @try {
            if (!session || !body || length == 0 || length > IPSW_SAP_MAX_SETUP) {
                return failed(IPSW_NATIVE_FAILED);
            }
            NSError *error = nil;
            NSData *data = [(id)session handshakeRequestWithCertificateData:[NSData dataWithBytes:body length:length] error:&error];
            return error ? failed_with_error(error) : copied_data(data, IPSW_SAP_MAX_SETUP);
        } @catch (NSException *exception) {
            (void)exception;
            return failed(IPSW_NATIVE_FAILED);
        }
    }
}

ipsw_native_result ipsw_sap_complete(void *session, const void *body, size_t length) {
    @autoreleasepool {
        @try {
            if (!session || !body || length == 0 || length > IPSW_SAP_MAX_SETUP) {
                return failed(IPSW_NATIVE_FAILED);
            }
            NSError *error = nil;
            BOOL completed = [(id)session completeWithHandshakeResponse:[NSData dataWithBytes:body length:length] error:&error];
            if (!completed || error) {
                return failed_with_error(error);
            }
            return failed(IPSW_NATIVE_OK);
        } @catch (NSException *exception) {
            (void)exception;
            return failed(IPSW_NATIVE_FAILED);
        }
    }
}

ipsw_native_result ipsw_sap_sign(void *session, const void *body, size_t length) {
    @autoreleasepool {
        @try {
            if (!session || (!body && length != 0) || length > IPSW_NATIVE_MAX_BODY) {
                return failed(IPSW_NATIVE_FAILED);
            }
            NSError *error = nil;
            NSData *data = [(id)session signData:[NSData dataWithBytes:body length:length] error:&error];
            return error ? failed_with_error(error) : copied_data(data, IPSW_NATIVE_MAX_SIGNATURE);
        } @catch (NSException *exception) {
            (void)exception;
            return failed(IPSW_NATIVE_FAILED);
        }
    }
}

void ipsw_sap_close(void *session) {
    if (!session) {
        return;
    }
    @autoreleasepool {
        @try {
            [(id)session invalidate];
        } @catch (NSException *exception) {
            (void)exception;
        } @finally {
            [(id)session release];
        }
    }
}

void ipsw_native_result_free(ipsw_native_result *result) {
    if (!result) {
        return;
    }
    if (result->bytes) {
        volatile uint8_t *bytes = result->bytes;
        for (size_t index = 0; index < result->length; index++) {
            bytes[index] = 0;
        }
        free(result->bytes);
    }
    result->bytes = NULL;
    result->length = 0;
}
