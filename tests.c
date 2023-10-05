#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include "salsa20.h"
#include "utils.h"

//Testing crypt by comparing message with encoded and decoded message
int test_salsa20_crypt(int n, char *message, size_t mlen, uint32_t key[8], uint64_t nonce) {
	uint8_t cipher[mlen];
	switch(n){
		case 0:
			salsa20_crypt(mlen, (uint8_t *)message, cipher, key, nonce);
			salsa20_crypt(mlen, cipher, cipher, key, nonce);
			break;
		case 1:
			salsa20_crypt_V1(mlen, (uint8_t *)message, cipher, key, nonce);
			salsa20_crypt_V1(mlen, cipher, cipher, key, nonce);
			break;
		case 2:
			salsa20_crypt_V2(mlen, (uint8_t *)message, cipher, key, nonce);
			salsa20_crypt_V2(mlen, cipher, cipher, key, nonce);
			break;
		case 3:
			salsa20_crypt_V3(mlen, (uint8_t *)message, cipher, key, nonce);
			salsa20_crypt_V3(mlen, cipher, cipher, key, nonce);
			break;
		case 4:
			salsa20_crypt_V4(mlen, (uint8_t *)message, cipher, key, nonce);
			salsa20_crypt_V4(mlen, cipher, cipher, key, nonce);
			break;
	}
	return memcmp(message, cipher, mlen);
}

// Testing core by comparing result of algorithm with right result
int test_salsa20_core(int version, uint32_t input[16], uint32_t rightResult[16]) {

	uint32_t output[16];
	switch (version) {
	case 0:
		salsa20_core(output, input);
		break;
	case 1:
		salsa20_core_V1(output, input);
		break;
	case 2:
		salsa20_core_V2(output, input);
		break;
	case 3:
		salsa20_core_V3(output, input);
		break;
	case 4:
		salsa20_core_V4(output, input);
		break;
	}

	return memcmp(rightResult, output, 16);
}

// run all defined tests
int run_tests() {
	int errorCounter = 0;
	int successCounter = 0;

	//Testcases for crypt
	char *cryptTests[5] = {"A\0", "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\0", "Eine unverschlüsselte Nachricht\0", "C is a general-purpose computer programming language. It was created in the 1970s by Dennis Ritchie, and remains very widely used and influential.\0", "Dies ist eine unverschlüsselte Nachricht. Nach der Verschlüsselung wird dieser Text nicht mehr lesbar sein.\0"}; // 3.test quoted from https://en.wikipedia.org/wiki/C_(programming_language)(access: 22.07.22)
	uint64_t cryptTestNonce[5] = {123, 987, 444, 232, 1112};
	uint32_t cryptTestKey[5][8] = {{1, 2, 3, 4, 5, 6, 7, 8}, {8, 7, 6, 5, 4, 3, 2, 1}, {3, 3, 3, 3, 3, 3, 3, 3}, {2, 1, 2, 3, 4, 5, 6, 7}, {5, 2, 7, 3, 7, 4, 2, 2}};
	size_t cryptTestLength[5] = {2, 41, 32, 143, 108};

	//Testcases for core
	uint32_t coreTests[5][16] = {
		{0x61707865, 0x00000000, 0x00000000, 0x00000000,
		 0x00000000, 0x3320646e, 0x00000000, 0x00000000,
		 0x00000000, 0x00000000, 0x79622d32, 0x00000000,
		 0x00000000, 0x00000000, 0x00000000, 0x6b206574},

		{0x61707865, 0x44332211, 0x21221112, 0x2af21262,
		 0xaabb4312, 0x3320646e, 0x2aa3ffab, 0xefefefef,
		 0x8083f21e, 0x14141414, 0x79622d32, 0x41414141,
		 0x3254a320, 0x4a445521, 0x11111111, 0x6b206574},

		{0x61707865, 0x00000001, 0x00000002, 0x00000003,
		 0x00000004, 0x3320646e, 0x00000005, 0x00000006,
		 0x00000007, 0x00000008, 0x79622d32, 0x00000009,
		 0x00000010, 0x00000011, 0x00000012, 0x6b206574},

		{0x61707865, 0x54342298, 0x76503121, 0x333351aa,
		 0x00000000, 0x3320646e, 0x00000005, 0x00000006,
		 0x00044002, 0x34331332, 0x79622d32, 0x9867aaf2,
		 0xabcdefed, 0xa32124aa, 0xdde22126, 0x6b206574},

		{0x61707865, 0x00000004, 0x00000021, 0x22010003,
		 0x00000001, 0x3320646e, 0x55abcdef, 0x90000009,
		 0x00000002, 0xaa43271a, 0x79622d32, 0x00faabcf,
		 0x00000003, 0x00000011, 0xbbc21212, 0x6b206574},
	};
	//outputs of algorithm with coreTests
	uint32_t coreTestsResults[5][16] = {
		{0x5bf6979a, 0x1b724c9b, 0x21670a96, 0xd4a8fc45,
		 0xf9672ee3, 0x79a91e11, 0x26489cce, 0xe6ee6a80,
		 0xdac0e93d, 0x1ef9d72b, 0x9b63b2bc, 0x25c689f9,
		 0x38bf291b, 0xdc9b9ad3, 0x4b5fc5e7, 0x392ac12a},

		{0x76132b4e, 0xc23b814e, 0x715a24c0, 0x14589ee4,
		 0x3827c6b9, 0x4505a2b, 0x3d201a4d, 0xc4aaca92,
		 0xc27f63a0, 0x830b0b06, 0xa507fa46, 0xe685f7,
		 0xf7e04c9b, 0x7a4deba0, 0x49445650, 0x50ada11f},

		{0xffc5c953, 0xb884f85e, 0x41e6bfbb, 0x6a231657,
		 0x986eae4d, 0xe8d5ba40, 0x688b03a0, 0x8ffa109e,
		 0x95e93d8f, 0x69599d4b, 0x63c2c457, 0x7067d4a4,
		 0x5d16941b, 0x23e13f75, 0xfc1c5c81, 0x58a9d503},

		{0x2e311ab0, 0x791a227, 0x2fa7d366, 0xc3484e5a, 
		 0xdb05dbdd, 0x129c042e, 0xe05066bc, 0xb9252644, 
		 0x94d4ad3d, 0x7534bd9b, 0xe1d92e76, 0xa4426d2c, 
		 0x89a0e879, 0xf23ab2e5, 0x19543362, 0x8d14c9ef},

		{0xd26fafc3, 0x189702fa, 0xdb9e49c, 0xceea798a, 
		 0xa719d23, 0xb5af251b, 0x69ce8a97, 0x6675c5c6, 
		 0x7547b66b, 0x75f5e01a, 0x65b0b39d, 0x76f571a7, 
		 0x37dcb7a1, 0xe838b2b6, 0xdd74489a, 0xfc545e7d},
	};

	printf("Starting tests...\n");
	//Testing crypt
	for(size_t i = 0; i < 5; i++){
		char *currentTest = cryptTests[i];
		
		printf("testcase crypt %li: \"%s\"\n", i + 1, currentTest);
		size_t mlen = cryptTestLength[i];

		// Testing crypt of all versions
		for(size_t j = 0; j < 5; j++){
			if (test_salsa20_crypt(j, cryptTests[i], mlen, cryptTestKey[i], cryptTestNonce[i]) != 0) {
				printf("test_salsa_crypt_V%li failed\n", j);
				errorCounter++;
			}
			else{
				printf("test_salsa_crypt_V%li successful\n", j);
				successCounter++;
			}
		}
		printf("\n");
	}
	printf("-------------------------\n");

	// Testing core
	for (size_t i = 0; i < 5; i++) {
		uint32_t *currentTest = coreTests[i];
		uint32_t *currentTestResults = coreTestsResults[i];
		printf("testcase core %li\n", i + 1);

		// Testing all versions
		for (size_t j = 0; j < 5; j++) {
			if (test_salsa20_core(j, currentTest, currentTestResults) != 0) {
				printf("test_salsa_core_V%li failed\n", j);
				errorCounter++;
			}
			else {
				printf("test_salsa_core_V%li successful\n", j);
				successCounter++;
			}
		}
		printf("\n");
	}

	printf("Summary:\n");
	printf("%i tests successful\n", successCounter);
	printf("%i tests failed\n", errorCounter);

	return 0;
}
