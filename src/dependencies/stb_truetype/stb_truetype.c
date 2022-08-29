typedef _Bool bool;
typedef unsigned long size_t;

const void* NULL = (void*)0;

extern double floor(double x);
extern double ceil(double x);
extern double sqrt(double x);
extern double pow(double base, double exponent);
extern double fmod(double x, double y);
extern double cos(double x);
extern double acos(double x);
extern double fabs(double x);
extern void* malloc(size_t size);
extern void free(void* ptr);
extern void assert(bool condition);
extern size_t strlen(const char* string);
extern void* memcpy(void* destination, const void* source, size_t size);
extern void* memset(void* destination, int ch, size_t size);

#define STBTT_ifloor(x)   ((int) floor(x))
#define STBTT_iceil(x)    ((int) ceil(x))
#define STBTT_sqrt(x)      sqrt(x)
#define STBTT_pow(x,y)     pow(x,y)
#define STBTT_fmod(x,y)    fmod(x,y)
#define STBTT_cos(x)       cos(x)
#define STBTT_acos(x)      acos(x)
#define STBTT_fabs(x)      fabs(x)
#define STBTT_malloc(x,u)  ((void)(u),malloc(x))
#define STBTT_free(x,u)    ((void)(u),free(x))
#define STBTT_assert(x)    assert(x)
#define STBTT_strlen(x)    strlen(x)
#define STBTT_memcpy       memcpy
#define STBTT_memset       memset

_Static_assert(sizeof(size_t) == 8);

#define STB_TRUETYPE_IMPLEMENTATION
#include "stb_truetype.h"

