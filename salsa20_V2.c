/*
 * Salsa20 Version 3 (no SIMD)
 * -> core without without transpose (rowround(columnround))
 */
#include "salsa20.h"

 /*
	* Fills matrix with following values
	* (0x61707865  K0          K1          K2)
	* (K3          0x3320646e  N0          N1)
	* (C0          C1          0x79622d32  K4)
	* (K5          K6          K7          0x6b206574)
	*/
void fill_matrix_V2(uint32_t matrix[16], uint32_t key[8], uint64_t nonce, uint64_t counter) {
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
void update_counter_V2(uint32_t matrix[16], uint64_t counter){
	matrix[a31] = counter;
	matrix[a32] = counter >> 32;
}

/*
 * Left rotate number by 'n'-bits
 * https://stackoverflow.com/questions/70130105/bit-shift-right-hand-operand-type
 */
uint32_t rotate_left_V2(uint32_t number, uint8_t n) {
	return (number << n) | (number >> (32 - n));
}
/*
 * Add two 4x4 matrices and write result in matrix1
 */
void add_matrix_V2(uint32_t matrix1[16], const uint32_t matrix2[16]) {
	for (int i = 0; i < 16; i++) {
		matrix1[i] = matrix1[i] + matrix2[i];
	}
}

/*
 * Salsa Core - create key stream block from input matrix
 */
void salsa20_core_V2(uint32_t output[16], const uint32_t input[16]) {

	// write input matrix in output
	memcpy(output, input, 64UL);

	// loop 10 rounds because for every round we modify both the columns and then rows 
	for (int i = 0; i < 10; i++) {
		// column1
		output[a21] ^= rotate_left_V2(output[a11] + output[a41], 7);
		output[a31] ^= rotate_left_V2(output[a11] + output[a21], 9);
		output[a41] ^= rotate_left_V2(output[a31] + output[a21], 13);
		output[a11] ^= rotate_left_V2(output[a41] + output[a31], 18);
		// column2
		output[a32] ^= rotate_left_V2(output[a22] + output[a12], 7);
		output[a42] ^= rotate_left_V2(output[a22] + output[a32], 9);
		output[a12] ^= rotate_left_V2(output[a42] + output[a32], 13);
		output[a22] ^= rotate_left_V2(output[a12] + output[a42], 18);
		// column3
		output[a43] ^= rotate_left_V2(output[a33] + output[a23], 7);
		output[a13] ^= rotate_left_V2(output[a33] + output[a43], 9);
		output[a23] ^= rotate_left_V2(output[a13] + output[a43], 13);
		output[a33] ^= rotate_left_V2(output[a23] + output[a13], 18);
		// column4
		output[a14] ^= rotate_left_V2(output[a44] + output[a34], 7);
		output[a24] ^= rotate_left_V2(output[a44] + output[a14], 9);
		output[a34] ^= rotate_left_V2(output[a24] + output[a14], 13);
		output[a44] ^= rotate_left_V2(output[a34] + output[a24], 18);

		// each row is a result of swaping the matrix indices of each column, e.g. a_x1,x2 => a_x2,x1
		// this way the matrix tanspose can be avoided

		// row1
		output[a12] ^= rotate_left_V2(output[a11] + output[a14], 7);
		output[a13] ^= rotate_left_V2(output[a11] + output[a12], 9);
		output[a14] ^= rotate_left_V2(output[a13] + output[a12], 13);
		output[a11] ^= rotate_left_V2(output[a14] + output[a13], 18);
		// row2
		output[a23] ^= rotate_left_V2(output[a22] + output[a21], 7);
		output[a24] ^= rotate_left_V2(output[a22] + output[a23], 9);
		output[a21] ^= rotate_left_V2(output[a24] + output[a23], 13);
		output[a22] ^= rotate_left_V2(output[a21] + output[a24], 18);
		// row3
		output[a34] ^= rotate_left_V2(output[a33] + output[a32], 7);
		output[a31] ^= rotate_left_V2(output[a33] + output[a34], 9);
		output[a32] ^= rotate_left_V2(output[a31] + output[a34], 13);
		output[a33] ^= rotate_left_V2(output[a32] + output[a31], 18);
		// row4
		output[a41] ^= rotate_left_V2(output[a44] + output[a43], 7);
		output[a42] ^= rotate_left_V2(output[a44] + output[a41], 9);
		output[a43] ^= rotate_left_V2(output[a42] + output[a41], 13);
		output[a44] ^= rotate_left_V2(output[a43] + output[a42], 18);
	}
	// O = A + S
	add_matrix_V2(output, input);
}

/*
 * Salsa20 Encryption / Decryption for a given mesage, key and nonce
 */
void salsa20_crypt_V2(size_t mlen, const uint8_t msg[mlen], uint8_t cipher[mlen], uint32_t key[8], uint64_t iv) {

	uint32_t matrix[16] = { 0 };
	uint32_t salsaBlock[16] = { 0 };
	uint8_t* cipherStream;
	uint64_t counter = 0;

	fill_matrix_V2(matrix, key, iv, counter);
	for (size_t i = 0; i < mlen; i++) {
		// after every 64 bytes, compute next block with block counter
		if (i % 64 == 0) {
			salsa20_core_V2(salsaBlock, matrix);
			cipherStream = (uint8_t*)salsaBlock;
			counter++;
			update_counter_V2(matrix,counter);
		}
		cipher[i] = msg[i] ^ cipherStream[i % 64];
	}
}
