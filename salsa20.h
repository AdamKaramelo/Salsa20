#ifndef TEAM152_SALSA20_H
#define TEAM152_SALSA20_H 1

#include <stdint.h>
#include <string.h>

#define a11 0
#define a12 1
#define a13 2
#define a14 3
#define a21 4
#define a22 5
#define a23 6
#define a24 7
#define a31 8
#define a32 9
#define a33 10
#define a34 11
#define a41 12
#define a42 13
#define a43 14
#define a44 15

void salsa20_core(uint32_t output[16], const uint32_t input[16]);
void salsa20_crypt(size_t mlen, const uint8_t msg[mlen], uint8_t cipher[mlen], uint32_t key[8], uint64_t iv);
void salsa20_core_V1(uint32_t output[16], const uint32_t input[16]);
void salsa20_crypt_V1(size_t mlen, const uint8_t msg[mlen], uint8_t cipher[mlen], uint32_t key[8], uint64_t iv);
void salsa20_core_V2(uint32_t output[16], const uint32_t input[16]);
void salsa20_crypt_V2(size_t mlen, const uint8_t msg[mlen], uint8_t cipher[mlen], uint32_t key[8], uint64_t iv);
void salsa20_core_V3(uint32_t output[16], const uint32_t input[16]);
void salsa20_crypt_V3(size_t mlen, const uint8_t msg[mlen], uint8_t cipher[mlen], uint32_t key[8], uint64_t iv);
#endif
