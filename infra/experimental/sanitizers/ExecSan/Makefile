.POSIX:
CC     = cc
CFLAGS = -std=c99 -Wall -Wextra -O3 -g3

all: clean execSan tripwire target

execSan: execSan.c
	$(CC) $(CFLAGS) -o $@ $^

tripwire: tripwire.cpp
	clang++ -o /tmp/$@ $^

target: target.cpp
	clang -fsanitize=fuzzer -o $@ $^

test:  all vuln.dict
	./execSan ./target -dict=vuln.dict

clean:
	rm -f execSan /tmp/tripwire target /tmp/injected
