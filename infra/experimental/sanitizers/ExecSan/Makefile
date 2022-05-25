.POSIX:
CC     = cc
CFLAGS = -std=c99 -Wall -Wextra -O3 -g3

all: clean detector pearl oyster

detector: detector.c
	$(CC) $(CFLAGS) -o $@ $^

sand: sand.cpp
	clang++ -o /tmp/$@ $^

oyster: oyster.cpp
	clang -fsanitize=fuzzer -o $@ $^

harvest:  detector sand oyster vuln.dict
	rm -f /tmp/pearl
	./$< ./oyster -dict=vuln.dict

clean:
	find . -type f -not \( -name "*c" -or -name "*cpp" -or -name 'Makefile' -or -name 'README.md' -or -name 'vuln.dict' \) -delete
