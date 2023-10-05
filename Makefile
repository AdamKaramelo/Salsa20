CC=gcc
FLAGS=-std=gnu11 -O3
DEBUG_FLAGS=-std=gnu11 -Wall -Wextra -Wpedantic -Wstrict-aliasing -fstrict-aliasing -g
FILES=main.c salsa20_V0.c salsa20_V1.c salsa20_V2.c salsa20_V3.c utils.c tests.c
OUT=salsa20

.PHONY: all clean
all: salsa20
salsa20: $(FILES)
	$(CC) $(FLAGS) -o $(OUT) $^
debug: $(FILES)
	$(CC) $(DEBUG_FLAGS) -o $(OUT) $^
clean:
	rm -f $(OUT)