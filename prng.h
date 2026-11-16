#ifndef PRNG_H
#define PRNG_H

#include <stdint.h>

class PRNG {
private:
    uint8_t state[256];
    uint64_t index;
public:
    PRNG();
    void seed(const uint8_t *entropy, size_t len);
    void random_bytes(uint8_t *output, size_t len);
};

#endif
