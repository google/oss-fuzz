.POSIX:
CXX     = clang++
CFLAGS = -std=c++17 -Wall -Wextra -O3 -g3

SystemSan: SystemSan.cpp
	$(CXX) $(CFLAGS) -lpthread -o $@ $^

run: clean SystemSan target.js
	./SystemSan jsfuzz ./target.js

clean:
	rm -f SystemSan /tmp/tripwire
