#include "prng.h"
#include "fips202.h"
#include <string.h>

PRNG::PRNG() {
    memset(state, 0, sizeof(state));
    index = 0;
}

void PRNG::seed(const uint8_t *entropy, size_t len) {
    Keccak(1088, 512, entropy, len, 0x1F, state, sizeof(state));
    index = 0;
}

void PRNG::random_bytes(uint8_t *output, size_t len) {
    for (size_t i = 0; i < len; ++i) {
        if (index >= sizeof(state)) {
            Keccak(1088, 512, state, sizeof(state), 0x1F, state, sizeof(state));
            index = 0;
        }
        output[i] = state[index++];
    }
}