typedef unsigned long size_t;
void* memcpy(void* destination, const void* source, size_t byte_count)
{
    char* dst = (char*)destination;
    const char* src = (const char*)source;

    for (size_t i = 0; i < byte_count; i += 1)
    {
        dst[i] = src[i];
    }

    return destination;
}

void* memset(void* destination, int character, size_t byte_count)
{
    char* dst = (char*)destination;
    char ch = (char)character;

    for (size_t i = 0; i < byte_count; i += 1)
    {
        dst[i] = ch;
    }

    return destination;
}

size_t strlen(const char* str)
{
    size_t length = 0;
    while (*str++)
    {
        length += 1;
    }

    return length;
}
