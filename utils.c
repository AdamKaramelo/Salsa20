#include "utils.h"

unsigned long long get_unsigned_long_long(char* charPointer, const char* errorMessage) {
	errno = 0;
	char* endPointer;
	unsigned long long number = strtoull(charPointer, &endPointer, 10);
	if (charPointer == endPointer || *endPointer != '\0' || errno != 0) {
		throw_error(errorMessage);
	}
	return number;
}
unsigned long get_unsigned_long(char* charPointer, const char* errorMessage) {
	errno = 0;
	char* endPointer;
	unsigned long number = strtoul(charPointer, &endPointer, 10);
	if (charPointer == endPointer || *endPointer != '\0' || errno != 0) {
		throw_error(errorMessage);
	}
	return number;
}
long long get_long_long(char* charPointer, const char* errorMessage) {
	errno = 0;
	char* endPointer;
	long long number = strtoll(charPointer, &endPointer, 10);
	if (charPointer == endPointer || *endPointer != '\0' || errno != 0) {
		throw_error(errorMessage);
	}
	return number;
}

void throw_error(const char* msg) {
	fprintf(stderr, "Error: %s\n", msg);
	exit(1);
}
void throw_perror(const char* msg) {
	perror(msg);
	exit(1);
}
void throw_file_error(const char* msg, FILE* file) {
	fprintf(stderr, "Error: %s\n", msg);
	if (file) fclose(file);
	exit(1);
}
void throw_file_perror(const char* msg, FILE* file) {
	perror(msg);
	if (file) fclose(file);
	exit(1);
}

/*
 * Parses key from char* and stores it in array of second parameter
 */
void parseKey(char* keyPtr, uint32_t key[8]) {
	// minimum key length: "0,0,0,0,0,0,0,0"
	// maximum key length: "4294967295,4294967295,4294967295,4294967295,4294967295,4294967295,4294967295,4294967295"
	if(strlen(keyPtr) > 87) {
		throw_error("Supplied key is too big");
	}
	// write keys in Little-endian order as specified in request email
	// keys are supplied as comma-separated list of 32-bit integers
	size_t counter = 0;
	char* integerAsCharPtr;
	while((integerAsCharPtr = strtok(keyPtr, ",")) != NULL && counter < 8) {
		keyPtr = NULL;
		if(*integerAsCharPtr == '-') {
			throw_error("A key number can not be negative");
		}
		const unsigned long number = get_unsigned_long(integerAsCharPtr, "Error parsing key number");
		if(number > UINT32_MAX) {
			throw_error("A number in the key is too big");
		}
		key[7 - counter] = number;
		counter++;
	}
	if(counter < 8) {
		throw_error("Key not fully supplied. Use eight 32-Bit integers for key");
	}
	if(integerAsCharPtr != NULL) {
		throw_error("Too many commas or too many integers supplied. Use eight 32-Bit integers for key");
	}
}
uint64_t parseNonce(char* noncePtr) {
	if(*noncePtr == '-') {
		throw_error("Initialization vector can not be negative");
	}
	const unsigned long long nonce = get_unsigned_long_long(noncePtr, "Supplied wrong initialization vector");

	if(nonce > UINT64_MAX) {
		throw_error("Initialization vector is too big");
	}
	return nonce;
}

void print_help() {
	char* help =
		"salsa20\n\n"
		"NAME\n\n"
		"\tsalsa20 - stream cypher algorithm used to encrypt/decrypt a message\n\n"
		"SYNOPSIS\n\n"
		"\tsalsa20 [-V=<DEFINED_VERSION>] [-B=<NUMBER_OF_FUNCTION_REPETITIONS>] [-o=<OUTPUT_FILE>] [-k=<KEY>] [-iv=<NONCE>] <INPUT_FILE> [-h]\n\n"
		"OPTIONS\n\n"
		"\t-V\tUsed version, default version is 0\n\n"
		"\t-B\tAmount of repetitions of salsa20_crypt function, default amount is 0\n\n"
		"\t-o\tPath to output file, default path is out.txt\n\n"
		"\t-h, --help\t Display help\n\n"
		"\t-T\t Executes testcases in tests.c for all the Versions with different Inputs\n\n"
		"EXECUTION\n\n"
		"\tmake - Compiles and creates an Executable\n\n"
		"EXAMPLES\n\n"
		"\t./salsa20 -k 1,2,3,4,5,6,7,8 -iv 12345 ./example/klartext.txt\n"
		"\t./salsa20 -V0 -B10 -k 94967295,42967294,42949672,4294967292,429496791,42496720,429496,1 -iv 12345 -o ./geheimtext.txt ./examples/klartext.txt\n\n";

	fprintf(stdout, "%s", help);
}
