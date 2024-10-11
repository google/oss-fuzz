.POSIX:
CXX     = clang++
CFLAGS = -std=c++20 -Wall -Wextra -O3 -g3 -Werror -static

all: tracer

tracer: tracer.cpp inspect_utils.cpp
	$(CXX) $(CFLAGS) -lpthread -o $@ $^

clean:
	rm -f tracer
