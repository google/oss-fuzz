.POSIX:
CXX     = clang++
CFLAGS = -std=c++17 -Wall -Wextra -O3 -g3

all: clean execSan tripwire target

execSan: execSan.cpp
	$(CXX) $(CFLAGS) -lpthread -o $@ $^

target: target.cpp
	$(CXX) $(CFLAGS) -fsanitize=address,fuzzer -o $@ $^

test:  all vuln.dict
	./execSan ./target -dict=vuln.dict

clean:
	rm -f execSan /tmp/tripwire target 
