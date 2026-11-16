#ifndef FIPS202_H
#define FIPS202_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

void Keccak(unsigned int rate, unsigned int capacity, const unsigned char *input, unsigned long long inputByteLen, unsigned char delimitedSuffix, unsigned char *output, unsigned long long outputByteLen);

#ifdef __cplusplus
}
#endif

#endif
