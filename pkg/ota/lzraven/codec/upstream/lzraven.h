#ifndef LZRAVEN_H
#define LZRAVEN_H

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

size_t lzraven_encode_bound(size_t size);
size_t lzraven_encode_buffer(void *destination, size_t capacity, const void *source, size_t size);
size_t lzraven_decode_buffer(void *destination, size_t capacity, const void *source, size_t size);
size_t lzraven_decode_scratch_size(void);
size_t lzraven_decode_buffer_with_scratch(void *destination, size_t capacity, const void *source, size_t size, void *scratch);

#ifdef __cplusplus
}
#endif

#endif
