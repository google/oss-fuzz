.POSIX:
CXX     = clang++
CFLAGS = -std=c++17 -Wall -Wextra -O3 -g3

execSan: execSan.cpp
	$(CXX) $(CFLAGS) -lpthread -o $@ $^

target: target.cpp
	$(CXX) $(CFLAGS) -fsanitize=address,fuzzer -o $@ $^

libnmap: clean execSan target
	$(CXX) $(CFLAGS) -fsanitize=address,fuzzer -o ./target ./target.cpp
	./execSan ./target

clean:
	rm -f execSan /tmp/tripwire target
