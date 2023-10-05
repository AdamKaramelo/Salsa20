/*
 * Salsa20 Version 0 (SIMD: crypt, add_matrix)
 * -> core without transpose (rowround(columnround))
 */
#include <emmintrin.h>
#include "salsa20.h"

 /*
	* Fills matrix with following values
	* (0x61707865  K0          K1          K2)
	* (K3          0x3320646e  N0          N1)
	* (C0          C1          0x79622d32  K4)
	* (K5          K6          K7          0x6b206574)
	*/
void fill_matrix(uint32_t matrix[16], uint32_t key[8], uint64_t nonce, uint64_t counter) {
	// write constants
	matrix[a11] = 0x61707865;
	matrix[a22] = 0x3320646e;
	matrix[a33] = 0x79622d32;
	matrix[a44] = 0x6b206574;

	// write nonce
	matrix[a23] = nonce;
	matrix[a24] = nonce >> 32;

	// write counter
	matrix[a31] = counter;
	matrix[a32] = counter >> 32;

	// write key
	for (int i = 0; i < 4; i++) {
		matrix[a21 - i] = key[a21 + i];
		matrix[a43 - i] = key[i];
	}
}

/*
 * Updates the counter value of the Matrix
 */
void update_counter(uint32_t matrix[16], uint64_t counter){
	matrix[a31] = counter;
	matrix[a32] = counter >> 32;
}

/*
 * Left rotate number by 'n'-bits
 * https://stackoverflow.com/questions/70130105/bit-shift-right-hand-operand-type
 */
uint32_t rotate_left(uint32_t number, uint8_t n) {
	return (number << n) | (number >> (32 - n));
}

/*
 * Add two 4x4 matrices using SIMD and write result in matrix1
 */
void add_matrix_SIMD(uint32_t matrix1[16], const uint32_t matrix2[16]) {
	__m128i val1;
	__m128i val2;
	for (int i = 0; i < 16; i += 4) {
		val1 = _mm_loadu_si128((__m128i*) (matrix1 + i));
		val2 = _mm_loadu_si128((__m128i*) (matrix2 + i));
		val1 = _mm_add_epi32(val1, val2);
		_mm_storeu_si128((__m128i*) (matrix1 + i), val1);
	}
}

/*
 * Salsa Core - create key stream block from input matrix
 */
void salsa20_core(uint32_t output[16], const uint32_t input[16]) {

	// write input matrix in output
	memcpy(output, input, 64UL);

	// loop 10 rounds because for every round we modify both the columns and then rows 
	for (int i = 0; i < 10; i++) {
		// column1
		output[a21] ^= rotate_left(output[a11] + output[a41], 7);
		output[a31] ^= rotate_left(output[a11] + output[a21], 9);
		output[a41] ^= rotate_left(output[a31] + output[a21], 13);
		output[a11] ^= rotate_left(output[a41] + output[a31], 18);
		// column2
		output[a32] ^= rotate_left(output[a22] + output[a12], 7);
		output[a42] ^= rotate_left(output[a22] + output[a32], 9);
		output[a12] ^= rotate_left(output[a42] + output[a32], 13);
		output[a22] ^= rotate_left(output[a12] + output[a42], 18);
		// column 3
		output[a43] ^= rotate_left(output[a33] + output[a23], 7);
		output[a13] ^= rotate_left(output[a33] + output[a43], 9);
		output[a23] ^= rotate_left(output[a13] + output[a43], 13);
		output[a33] ^= rotate_left(output[a23] + output[a13], 18);
		// column 4
		output[a14] ^= rotate_left(output[a44] + output[a34], 7);
		output[a24] ^= rotate_left(output[a44] + output[a14], 9);
		output[a34] ^= rotate_left(output[a24] + output[a14], 13);
		output[a44] ^= rotate_left(output[a34] + output[a24], 18);

		// each row is a result of swaping the matrix indices of each column, e.g. a_x1,x2 => a_x2,x1
		// this way the matrix tanspose can be avoided

		// row1
		output[a12] ^= rotate_left(output[a11] + output[a14], 7);
		output[a13] ^= rotate_left(output[a11] + output[a12], 9);
		output[a14] ^= rotate_left(output[a13] + output[a12], 13);
		output[a11] ^= rotate_left(output[a14] + output[a13], 18);
		// row2
		output[a23] ^= rotate_left(output[a22] + output[a21], 7);
		output[a24] ^= rotate_left(output[a22] + output[a23], 9);
		output[a21] ^= rotate_left(output[a24] + output[a23], 13);
		output[a22] ^= rotate_left(output[a21] + output[a24], 18);
		// row3
		output[a34] ^= rotate_left(output[a33] + output[a32], 7);
		output[a31] ^= rotate_left(output[a33] + output[a34], 9);
		output[a32] ^= rotate_left(output[a31] + output[a34], 13);
		output[a33] ^= rotate_left(output[a32] + output[a31], 18);
		// row4
		output[a41] ^= rotate_left(output[a44] + output[a43], 7);
		output[a42] ^= rotate_left(output[a44] + output[a41], 9);
		output[a43] ^= rotate_left(output[a42] + output[a41], 13);
		output[a44] ^= rotate_left(output[a43] + output[a42], 18);
	}
	// O = A + S
	add_matrix_SIMD(output, input);
}

/*
 * Salsa20 Encryption / Decryption for a given mesage, key and nonce
 */
void salsa20_crypt(size_t mlen, const uint8_t msg[mlen], uint8_t cipher[mlen], uint32_t key[8], uint64_t iv) {

	uint32_t matrix[16] = { 0 };
	uint32_t salsaBlock[16] = { 0 };
	uint8_t* cipherStream;
	uint64_t counter = 0;
	size_t blocks = mlen % 64 > 0 ? (mlen / 64) + 1 : mlen / 64;
	size_t outIndex = 0;
	size_t i = 0;

	// cipher 64 byte blocks of message
	fill_matrix(matrix, key, iv, counter);
	for (; i < blocks - 1; i++) {
		salsa20_core(salsaBlock, matrix);
		cipherStream = (uint8_t*)salsaBlock;

		// cipher using SIMD
		for (size_t j = 0; j < 4; j++, outIndex += 16) {
			_mm_storeu_si128((__m128i*)(cipher + outIndex), _mm_xor_si128(_mm_loadu_si128((__m128i*)(cipherStream + j * 16)), _mm_loadu_si128((__m128i*)(msg + outIndex))));
		}
		counter++;
		update_counter(matrix,counter);
	}

	// last block
	// create cipherStream for last block
	update_counter(matrix,counter);
	salsa20_core(salsaBlock, matrix);
	cipherStream = (uint8_t*)salsaBlock;

	// cipher 16 byte blocks of message using SIMD
	size_t rest = mlen % 64;
	rest = rest == 0 ? 64 : rest;
	for (i = 0; i < rest - (rest % 16); i += 16) {
		_mm_storeu_si128(
			(__m128i*) (cipher + outIndex + i),
			_mm_xor_si128(_mm_loadu_si128((__m128i*) (cipherStream + i)), _mm_loadu_si128((__m128i*) (msg + outIndex + i))
			));
	}

	// cipher remaining bytes of message without SIMD
	for (; i < rest; i++) {
		cipher[outIndex + i] = msg[outIndex + i] ^ cipherStream[i];
	}
}
