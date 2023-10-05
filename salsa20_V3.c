/*
 * Salsa20 Version 4 (no SIMD)
 * -> core according to task definition (../GRA_0500.pdf)
 */
#include "salsa20.h"
#include <emmintrin.h>

 /*
	* Fills matrix with following values
	* (0x61707865  K0          K1          K2)
	* (K3          0x3320646e  N0          N1)
	* (C0          C1          0x79622d32  K4)
	* (K5          K6          K7          0x6b206574)
	*/
void fill_matrix_V3(uint32_t matrix[16], uint32_t key[8], uint64_t nonce, uint64_t counter) {
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
void update_counter_V3(uint32_t matrix[16], uint64_t counter){
	matrix[a31] = counter;
	matrix[a32] = counter >> 32;
}

/*
 * Left rotate number by 'n'-bits
 * https://stackoverflow.com/questions/70130105/bit-shift-right-hand-operand-type
 */
uint32_t rotate_left_V3(uint32_t number, uint8_t n) {
	return (number << n) | (number >> (32 - n));
}
/*
 * Add two 4x4 matrices and write result in matrix1
 */
void add_matrix_V3(uint32_t matrix1[16], const uint32_t matrix2[16]) {
	for (int i = 0; i < 16; i++) {
		matrix1[i] = matrix1[i] + matrix2[i];
	}
}

/*
 * Swap entry at position 'a' with entry at position 'b'
 */
void swap_V3(uint32_t matrix[], uint8_t a, uint8_t b) {
	uint32_t temp = matrix[a];
	matrix[a] = matrix[b];
	matrix[b] = temp;
}

/*
 * Transpose a 4x4 matrix
 */
void transpose_matrix_V3(uint32_t matrix[16]) {
	swap_V3(matrix, a12, a21);
	swap_V3(matrix, a13, a31);
	swap_V3(matrix, a14, a41);
	swap_V3(matrix, a23, a32);
	swap_V3(matrix, a24, a42);
	swap_V3(matrix, a34, a43);
}

/*
 * Salsa Core - create key stream block from input matrix
 */
void salsa20_core_V3(uint32_t output[16], const uint32_t input[16]) {

	// write matrix matrix in output
	memcpy(output, input, 64UL);

	// loop 20 rounds
	for (int i = 0; i < 20; i++) {
		// rotate left by 7
		output[a21] ^= rotate_left_V3(output[a11] + output[a41], 7); // K3
		output[a32] ^= rotate_left_V3(output[a22] + output[a12], 7);  // c1
		output[a43] ^= rotate_left_V3(output[a33] + output[a23], 7); // K7
		output[a14] ^= rotate_left_V3(output[a44] + output[a34], 7); // K2

		// rotate left by 9
		output[a31] ^= rotate_left_V3(output[a11] + output[a21], 9);  // c0
		output[a42] ^= rotate_left_V3(output[a22] + output[a32], 9);  // k6
		output[a13] ^= rotate_left_V3(output[a33] + output[a43], 9); // K1
		output[a24] ^= rotate_left_V3(output[a44] + output[a14], 9);  // N1

		// rotate left by 13
		output[a41] ^= rotate_left_V3(output[a31] + output[a21], 13); // K5
		output[a12] ^= rotate_left_V3(output[a42] + output[a32], 13); // K0
		output[a23] ^= rotate_left_V3(output[a13] + output[a43], 13); // N0
		output[a34] ^= rotate_left_V3(output[a24] + output[a14], 13); // K4

		// rotate left by 18
		output[a11] ^= rotate_left_V3(output[a41] + output[a31], 18);
		output[a22] ^= rotate_left_V3(output[a12] + output[a42], 18);
		output[a33] ^= rotate_left_V3(output[a23] + output[a13], 18);
		output[a44] ^= rotate_left_V3(output[a34] + output[a24], 18);

		transpose_matrix_V3(output);
	}
	// O = A + S
	add_matrix_V3(output, input);
}

/*
 * Salsa20 Encryption / Decryption for a given mesage, key and nonce
 */
void salsa20_crypt_V3(size_t mlen, const uint8_t msg[mlen], uint8_t cipher[mlen], uint32_t key[8], uint64_t iv) {

	uint32_t matrix[16] = { 0 };
	uint32_t salsaBlock[16] = { 0 };
	uint8_t* cipherStream;
	uint64_t counter = 0;

	fill_matrix_V3(matrix, key, iv, counter);
	for (size_t i = 0; i < mlen; i++) {
		// after every 64 bytes, compute next block with block counter
		if (i % 64 == 0) {
			salsa20_core_V3(salsaBlock, matrix);
			cipherStream = (uint8_t*)salsaBlock;
			counter++;
			update_counter_V3(matrix,counter);
		}
		cipher[i] = msg[i] ^ cipherStream[i % 64];
	}
}
