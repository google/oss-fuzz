.POSIX:
CXX     = clang++
CFLAGS = -std=c++17 -Wall -Wextra -O3 -g3

SystemSan: SystemSan.cpp
	$(CXX) $(CFLAGS) -lpthread -o $@ $^

run: clean SystemSan fuzz_pytorch_lightning.py
	./SystemSan ./fuzz_pytorch_lightning.py -dict=vuln.dict

clean:
	rm -f SystemSan /tmp/tripwire
