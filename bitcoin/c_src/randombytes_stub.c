#include <stddef.h>
#include <stdint.h>

int randombytes(uint8_t *buf, size_t n)
{
    for (size_t i = 0; i < n; ++i) buf[i] = 0;
    return 0;
}
