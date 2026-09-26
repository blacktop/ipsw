#ifndef IPSW_CAR_RENDER_H
#define IPSW_CAR_RENDER_H

#include <stddef.h>

typedef struct ipsw_car_render ipsw_car_render;

const char *ipsw_car_render_open(const unsigned char *data, size_t length, int kind,
                               size_t limit, ipsw_car_render **result,
                               size_t *width, size_t *height);
const char *ipsw_car_render_draw(ipsw_car_render *source, size_t width, size_t height,
                               unsigned char *pixels, size_t length);
void ipsw_car_render_close(ipsw_car_render *source);

#endif
