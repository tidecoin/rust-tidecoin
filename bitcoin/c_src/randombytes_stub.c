// SPDX-License-Identifier: CC0-1.0

#include <stddef.h>
#include <stdint.h>

int randombytes(uint8_t* buf, size_t len)
{
    if (buf == NULL) return 0;
    for (size_t i = 0; i < len; ++i) {
        buf[i] = 0;
    }
    return 0;
}
