/*
 * Salsa20 Version 1 (full SIMD)
 * -> core with transpose
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
void fill_matrix_V1(uint32_t matrix[16], uint32_t key[8], uint64_t nonce, uint64_t counter) {
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
void update_counter_V1(uint32_t matrix[16], uint64_t counter){
	matrix[a31] = counter;
	matrix[a32] = counter >> 32;
}

/*
 * Salsa Core - create key stream block from input matrix
 */
void salsa20_core_V1(uint32_t output[16], const uint32_t input[16]) {

	uint32_t firstDiagonalArray[4] = { input[a21], input[a32], input[a43], input[a14] };
	uint32_t secondDiagonalArray[4] = { input[a31], input[a42], input[a13], input[a24] };
	uint32_t thirdDiagonalArray[4] = { input[a41], input[a12], input[a23], input[a34] };
	uint32_t fourthDiagonalArray[4] = { input[a11], input[a22], input[a33], input[a44] };

	__m128i firstDiagonal = _mm_load_si128((__m128i*) firstDiagonalArray);
	__m128i secondDiagonal = _mm_load_si128((__m128i*) secondDiagonalArray);
	__m128i thirdDiagonal = _mm_load_si128((__m128i*) thirdDiagonalArray);
	__m128i fourthDiagonal = _mm_load_si128((__m128i*) fourthDiagonalArray);
	__m128i temp;
	__m128i temp2;

	for (int i = 0; i < 20; i++) {
		// first block: left rotate 7
		temp = _mm_add_epi32(fourthDiagonal, thirdDiagonal);
		temp2 = _mm_slli_epi32(temp, 7);
		temp = _mm_srli_epi32(temp, 25);
		temp = _mm_or_si128(temp, temp2);
		firstDiagonal = _mm_xor_si128(temp, firstDiagonal);

		// second block: left rotate 9
		temp = _mm_add_epi32(firstDiagonal, fourthDiagonal);
		temp2 = _mm_slli_epi32(temp, 9);
		temp = _mm_srli_epi32(temp, 23);
		temp = _mm_or_si128(temp, temp2);
		secondDiagonal = _mm_xor_si128(temp, secondDiagonal);

		// third block: left rotate 13
		temp = _mm_add_epi32(secondDiagonal, firstDiagonal);
		temp2 = _mm_slli_epi32(temp, 13);
		temp = _mm_srli_epi32(temp, 19);
		temp = _mm_or_si128(temp, temp2);
		thirdDiagonal = _mm_xor_si128(temp, thirdDiagonal);

		// fourth block: left rotate 18
		temp = _mm_add_epi32(thirdDiagonal, secondDiagonal);
		temp2 = _mm_slli_epi32(temp, 18);
		temp = _mm_srli_epi32(temp, 14);
		temp = _mm_or_si128(temp, temp2);
		fourthDiagonal = _mm_xor_si128(temp, fourthDiagonal);

		// transpose
		temp = _mm_shuffle_epi32(firstDiagonal, 147); // 2, 1 0, 3
		firstDiagonal = _mm_shuffle_epi32(thirdDiagonal, 57); // 0, 3, 2, 1
		thirdDiagonal = temp;
		secondDiagonal = _mm_shuffle_epi32(secondDiagonal, 78); // 1, 0, 3, 2
	}

	// O = A + S
	firstDiagonal = _mm_add_epi32(firstDiagonal, _mm_load_si128((__m128i*) firstDiagonalArray));
	secondDiagonal = _mm_add_epi32(secondDiagonal, _mm_load_si128((__m128i*) secondDiagonalArray));
	thirdDiagonal = _mm_add_epi32(thirdDiagonal, _mm_load_si128((__m128i*) thirdDiagonalArray));
	fourthDiagonal = _mm_add_epi32(fourthDiagonal, _mm_load_si128((__m128i*) fourthDiagonalArray));

	_mm_store_si128((__m128i*) firstDiagonalArray, firstDiagonal);
	_mm_store_si128((__m128i*) secondDiagonalArray, secondDiagonal);
	_mm_store_si128((__m128i*) thirdDiagonalArray, thirdDiagonal);
	_mm_store_si128((__m128i*) fourthDiagonalArray, fourthDiagonal);

	for (int i = 0; i < 4; i++) {
		output[(i * 5 + a21) % 16] = firstDiagonalArray[i];
		output[(i * 5 + a31) % 16] = secondDiagonalArray[i];
		output[(i * 5 + a41) % 16] = thirdDiagonalArray[i];
		output[i * 5] = fourthDiagonalArray[i];
	}
}

/*
 * Salsa20 Encryption / Decryption for a given mesage, key and nonce
 */
void salsa20_crypt_V1(size_t mlen, const uint8_t msg[mlen], uint8_t cipher[mlen], uint32_t key[8], uint64_t iv) {

	uint32_t matrix[16] = { 0 };
	uint32_t salsaBlock[16] = { 0 };
	uint8_t* cipherStream;
	uint64_t counter = 0;
	size_t blocks = mlen % 64 > 0 ? (mlen / 64) + 1 : mlen / 64;
	size_t outIndex = 0;
	size_t i = 0;

	// cipher 64 byte blocks of message
	fill_matrix_V1(matrix, key, iv, counter);
	for (; i < blocks - 1; i++) {
		salsa20_core_V1(salsaBlock, matrix);
		cipherStream = (uint8_t*)salsaBlock;

		// cipher using SIMD
		for (size_t j = 0; j < 4; j++, outIndex += 16) {
			_mm_storeu_si128((__m128i*)(cipher + outIndex), _mm_xor_si128(_mm_loadu_si128((__m128i*)(cipherStream + j * 16)), _mm_loadu_si128((__m128i*)(msg + outIndex))));
		}
		counter++;
		update_counter_V1(matrix,counter);
	}

	// last block
	// create cipherStream for last block
	update_counter_V1(matrix,counter);
	salsa20_core_V1(salsaBlock, matrix);
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
