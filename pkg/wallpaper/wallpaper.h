#ifndef WALLPAPER_H
#define WALLPAPER_H

#include <stdlib.h>

typedef struct {
    char* message;
    int code;
} wallpaper_error_t;

#ifdef __cplusplus
extern "C" {
#endif

// Parse CAML file and return wallpaper data
// Returns a pointer to the data buffer that must be freed by the caller
// Sets outSize to the size of the returned buffer
unsigned char* parse_caml_wallpaper(const char* path, size_t* outSize, wallpaper_error_t* error);

// Extract images from CAML file to the specified output directory
// Returns an array of strings containing paths to extracted images
// numImages is set to the number of extracted images
// The caller is responsible for freeing both the array and its contents
char** extract_caml_images(const char* path, const char* outputDir, int* numImages, wallpaper_error_t* error);

#ifdef __cplusplus
}
#endif

#endif /* WALLPAPER_H */