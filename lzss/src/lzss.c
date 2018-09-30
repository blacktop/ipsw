/*
 * Copyright (c) 2000 Apple Computer, Inc. All rights reserved.
 *
 * @APPLE_LICENSE_HEADER_START@
 *
 * The contents of this file constitute Original Code as defined in and
 * are subject to the Apple Public Source License Version 1.1 (the
 * "License").  You may not use this file except in compliance with the
 * License.  Please obtain a copy of the License at
 * http://www.apple.com/publicsource and read it before using this file.
 *
 * This Original Code and all software distributed under the License are
 * distributed on an "AS IS" basis, WITHOUT WARRANTY OF ANY KIND, EITHER
 * EXPRESS OR IMPLIED, AND APPLE HEREBY DISCLAIMS ALL SUCH WARRANTIES,
 * INCLUDING WITHOUT LIMITATION, ANY WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE OR NON-INFRINGEMENT.  Please see the
 * License for the specific language governing rights and limitations
 * under the License.
 *
 * @APPLE_LICENSE_HEADER_END@
 */
/**************************************************************
 LZSS.C -- A Data Compression Program
***************************************************************
    4/6/1989 Haruhiko Okumura
    Use, distribute, and modify this program freely.
    Please send me your improved versions.
        PC-VAN      SCIENCE
        NIFTY-Serve PAF01022
        CompuServe  74050,1022

**************************************************************/
/*
 *  lzss.c - Package for decompressing lzss compressed objects
 *
 *  Copyright (c) 2003 Apple Computer, Inc.
 *
 *  DRI: Josh de Cesare
 */
#include "lzss.h"

#define N 4096      /* size of ring buffer - must be power of 2 */
#define F 18        /* upper limit for match_length */
#define THRESHOLD 2 /* encode string into position and length \
                       if match_length is greater than this */
#define NIL N       /* index for root of binary search trees */

int decompress_lzss(u_int8_t *dst, u_int8_t *src, u_int32_t srclen)
{
    /* ring buffer of size N, with extra F-1 bytes to aid string comparison */
    u_int8_t text_buf[N + F - 1];
    u_int8_t *dststart = dst;
    u_int8_t *srcend = src + srclen;
    int i, j, k, r, c;
    unsigned int flags;

    dst = dststart;
    srcend = src + srclen;
    for (i = 0; i < N - F; i++)
        text_buf[i] = ' ';
    r = N - F;
    flags = 0;
    for (;;)
    {
        if (((flags >>= 1) & 0x100) == 0)
        {
            if (src < srcend)
                c = *src++;
            else
                break;
            flags = c | 0xFF00; /* uses higher byte cleverly */
        }                       /* to count eight */
        if (flags & 1)
        {
            if (src < srcend)
                c = *src++;
            else
                break;
            *dst++ = c;
            text_buf[r++] = c;
            r &= (N - 1);
        }
        else
        {
            if (src < srcend)
                i = *src++;
            else
                break;
            if (src < srcend)
                j = *src++;
            else
                break;
            i |= ((j & 0xF0) << 4);
            j = (j & 0x0F) + THRESHOLD;
            for (k = 0; k <= j; k++)
            {
                c = text_buf[(i + k) & (N - 1)];
                *dst++ = c;
                text_buf[r++] = c;
                r &= (N - 1);
            }
        }
    }

    return dst - dststart;
}