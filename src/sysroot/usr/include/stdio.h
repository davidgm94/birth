#pragma once

// TODO: implement
typedef struct FILE {
    int foo;
} FILE;

// TODO: implement
#define stderr -1

int fflush(FILE* stream);
int fprintf(FILE* restrict stream, const char* restrict format, ...);
