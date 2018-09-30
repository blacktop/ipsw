#include <sl.h>

#ifndef _LZSS_H
#define _LZSS_H

int decompress_lzss(u_int8_t *dst, u_int8_t *src, u_int32_t srclen);

#endif