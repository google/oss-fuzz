.POSIX:
CC     = cc
CFLAGS = -std=c99 -Wall -Wextra -O3 -g3

all: clean detector bomb target

detector: detector.c
	$(CC) $(CFLAGS) -o $@ $^

bomb: ExecSanBomb.cpp
	clang++ -o /tmp/$@ $^

target: ExecSanTest.cpp
	clang -fsanitize=fuzzer -o $@ $^

test:  detector bomb target vuln.dict
	rm -f /tmp/bombfile
	./$< ./target -dict=vuln.dict

clean:
	find . -type f -not \( -name "*c" -or -name "*cpp" -or -name 'Makefile' -or -name 'README.md' -or -name 'vuln.dict' \) -delete
