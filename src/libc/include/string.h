#pragma once

typedef unsigned long size_t;

void* memcpy(void* restrict destination, const void* restrict source, size_t byte_count);
void* memset(void* destination, int character, size_t count);
size_t strlen(const char* str);
