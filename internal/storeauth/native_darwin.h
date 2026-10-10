#ifndef IPSW_STOREAUTH_NATIVE_H
#define IPSW_STOREAUTH_NATIVE_H

#include <stddef.h>
#include <stdint.h>

enum {
    IPSW_NATIVE_OK = 0,
    IPSW_NATIVE_UNAVAILABLE = 1,
    IPSW_NATIVE_FAILED = 2
};

typedef struct {
    uint8_t *bytes;
    size_t length;
    int status;
    char error_domain[128];
    int64_t error_code;
} ipsw_native_result;

int ipsw_native_supported(void);
ipsw_native_result ipsw_native_headers(void);
ipsw_native_result ipsw_native_sign(const void *body, size_t length, double timeout);
void *ipsw_sap_open(ipsw_native_result *error);
ipsw_native_result ipsw_sap_handshake(void *session, const void *body, size_t length);
ipsw_native_result ipsw_sap_complete(void *session, const void *body, size_t length);
ipsw_native_result ipsw_sap_sign(void *session, const void *body, size_t length);
void ipsw_sap_close(void *session);
void ipsw_native_result_free(ipsw_native_result *result);

#endif
