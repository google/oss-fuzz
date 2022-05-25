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
	rm -f detector target /tmp/bomb /tmp/bombfile
