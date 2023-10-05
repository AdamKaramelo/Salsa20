#ifndef TEAM152_UTILS_H
#define TEAM152_UTILS_H 1

#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <stdint.h>
#include <stdlib.h> // EXIT_SUCCESS

unsigned long long get_unsigned_long_long(char* charPointer, const char* errorMessage) ;
unsigned long get_unsigned_long(char* charPointer, const char* errorMessage);
long long get_long_long(char* charPointer, const char* errorMessage);
void throw_error(const char* msg) ;
void throw_perror(const char* msg);
void throw_file_error(const char* msg, FILE* file);
void throw_file_perror(const char* msg, FILE* file);
void parseKey(char* keyPtr, uint32_t key[8]);
uint64_t parseNonce(char* noncePtr);
void print_help();
#endif
