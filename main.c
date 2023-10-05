#define _FILE_OFFSET_BITS 64 // https://linux.die.net/man/3/ftello
#include <getopt.h> // getopt_long
#include <stdint.h> // uint
#include <sys/stat.h> // fstat
#include <string.h> // strlen
#include <time.h> // timespec
#include <stdlib.h> // EXIT_SUCCESS
#include <stdbool.h>
#include "utils.h"
#include "salsa20.h"
#include "tests.h"

int main(int argc, char* argv[]) {

	// Function Pointer
	void (*salsa20CryptFunctions[])(size_t mlen, const uint8_t msg[mlen], uint8_t cipher[mlen], uint32_t key[8], uint64_t iv) = { salsa20_crypt, salsa20_crypt_V1, salsa20_crypt_V2, salsa20_crypt_V3};

	const int versionCount = sizeof(salsa20CryptFunctions) / sizeof(salsa20CryptFunctions[0]);

	// Long Options
	const struct option helpOption = {
		"help", // name
		0, // has_arg?
		NULL, // flag
		'h' // val
	};

	const struct option emptyOption = { 0,0,0,0 };
	const struct option longOptions[] = { helpOption, emptyOption };

	// Variables
	long long version = 0;
	long long benchmarkRepetitions = 0;
	char* inputFileString = NULL;
	char* outputFileString = "out.txt";
	uint32_t key[8] = {0};
	uint64_t nonce = 0;
	bool isBenchmarkSet = false;
	bool isKeySet = false;
	bool isNonceSet = false;

	int opt;

	while ((opt = getopt_long(argc, argv, "TV:B:k:i:o:h", longOptions, NULL)) != -1) {
		switch (opt) {
		case 'V':
			version = get_long_long(optarg, "Supplied version number is not a number");	
			break;
		case 'B':
			benchmarkRepetitions = get_long_long(optarg, "Supplied repetiton number is not correct");
			isBenchmarkSet = true;
			break;
		case 'T':
			run_tests();
			exit(0);
		case 'k':
			parseKey(optarg, key);
			isKeySet = true;
			break;
		case 'i':
			nonce = parseNonce(optarg);
			isNonceSet = true;
			break;
		case 'o':
			outputFileString = optarg;
			break;
		case 'h':
			print_help();
			if (argc == 2) return EXIT_SUCCESS;
			break;
		default:
			throw_error("An option was not detected or an error occured");
			return EXIT_FAILURE;
		}
	}

	if (version < 0 || version > versionCount) {
		char error[71] = {0};
		snprintf(error, 71, "%s %d", "Version does not exist, make sure to specify a version between 0 and", versionCount - 1);
		throw_error(error);
	}
	if (benchmarkRepetitions < 0) {
		throw_error("Too few repetitions specified");
	}
	if(!isKeySet) {
		throw_error("Key is not specified");
	}
	if(!isNonceSet) {
		throw_error("Initialization vector is not specified");
	}
	if (optind >= argc) {
		throw_error("Input file is not specified");
	}
	if (optind + 1 != argc) {
		throw_error("Too many (positional) arguments specified");
	}
	inputFileString = argv[optind];

	// open input file
	// https://man7.org/linux/man-pages/man3/fopen.3.html
	FILE* inputFilePointer = fopen(inputFileString, "r");
	if (inputFilePointer == NULL) {
		throw_file_perror("Error when opening input file", inputFilePointer);
		return EXIT_FAILURE;
	}

	// get file descriptor of input file
	// https://man7.org/linux/man-pages/man3/fileno.3.html
	int inputFileDescriptor = fileno(inputFilePointer);
	if (inputFileDescriptor == -1) {
		throw_file_perror("Error when getting information about file", inputFilePointer); // TODO
	}

	// get stat of input file
	// https://man7.org/linux/man-pages/man3/fstat.3p.html
	struct stat inputFileStat;
	if (fstat(inputFileDescriptor, &inputFileStat) != 0) {
		throw_file_perror("Error when getting information about file", inputFilePointer);
	}

	// is regular file
	// https://man7.org/linux/man-pages/man0/sys_stat.h.0p.html
	if (!S_ISREG(inputFileStat.st_mode)) {
		throw_file_error("File provided is not a regular file", inputFilePointer);
	}

	// is input fileLength greater 0
	if (inputFileStat.st_size <= 0) {
		throw_file_error("Please provide a non-empty file", inputFilePointer);
	}

	// store fileLength (equal for input & output)
	uint64_t fileLength = inputFileStat.st_size;

	// malloc inputBuffer
	uint8_t* inputBuffer = (uint8_t*)malloc(fileLength);
	if (inputBuffer == NULL) {
		throw_file_perror("An error occurred when allocating memory", inputFilePointer);
	}

	// read file into inputBuffer
	// https://man7.org/linux/man-pages/man3/fgets.3p.html
	if (fread(inputBuffer, 1, fileLength, inputFilePointer) < fileLength) {
		throw_file_perror("An error occurred when reading input file", inputFilePointer);
	}

	// close inputFilePointer
	if (fclose(inputFilePointer) != 0) {
		throw_perror("An error occurred when closing the file");
	}

	// malloc outputBuffer
	uint8_t* outputBuffer = (uint8_t*)malloc(fileLength);
	if (outputBuffer == NULL) {
		throw_perror("An error occurred when allocating memory");
	}

	if (isBenchmarkSet) {
		double totalTime = 0;
		struct timespec t1;
		struct timespec t2;
		for (int i = 0; i <= benchmarkRepetitions; i++) {
			clock_gettime(CLOCK_MONOTONIC, &t1);
			(*salsa20CryptFunctions[version])(fileLength, inputBuffer, outputBuffer, key, nonce);
			clock_gettime(CLOCK_MONOTONIC, &t2);
			totalTime += (t2.tv_sec + t2.tv_nsec * 1e-9) - (t1.tv_sec + t1.tv_nsec * 1e-9);
		}
		printf("Total run-time: %f | Average time per run: %f \n", totalTime, totalTime / (benchmarkRepetitions + 1));
	}
	else {
		(*salsa20CryptFunctions[version])(fileLength, inputBuffer, outputBuffer, key, nonce);
	}

	// open output file
	FILE* outputFilePointer = fopen(outputFileString, "w");
	if (outputFilePointer == NULL) {
		throw_file_perror("An error occurred when opening output file", outputFilePointer);
	}
	size_t bytesWritten = fwrite(outputBuffer, sizeof(uint8_t), fileLength, outputFilePointer);
	if (bytesWritten < fileLength) {
		throw_file_perror("An error occurred when writing output", outputFilePointer);
	}

	if (fclose(outputFilePointer) != 0) {
		throw_error("An error occurred when closing the output file");
	}

	free(inputBuffer);
	free(outputBuffer);

	return EXIT_SUCCESS;
}
