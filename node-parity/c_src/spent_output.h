// SPDX-License-Identifier: CC0-1.0
#ifndef TIDECOIN_PARITY_SPENT_OUTPUT_H
#define TIDECOIN_PARITY_SPENT_OUTPUT_H

#include <stddef.h>
#include <stdint.h>

// Keep in sync with ffi::NodeSpentOutput. Borrowed only for the duration of a call.
typedef struct {
    int64_t amount;
    const uint8_t* script;
    size_t script_len;
} TidecoinSpentOutput;

#endif
