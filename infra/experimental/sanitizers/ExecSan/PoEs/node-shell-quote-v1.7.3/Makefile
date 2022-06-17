.POSIX:
CXX     = clang++
CFLAGS = -std=c++17 -Wall -Wextra -O3 -g3

execSan: execSan.cpp
	$(CXX) $(CFLAGS) -lpthread -o $@ $^

run: clean execSan target.js
	./execSan jsfuzz ./target.js

clean:
	rm -f execSan /tmp/tripwire
