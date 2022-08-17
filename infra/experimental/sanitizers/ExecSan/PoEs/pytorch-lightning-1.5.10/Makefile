.POSIX:
CXX     = clang++
CFLAGS = -std=c++17 -Wall -Wextra -O3 -g3

execSan: execSan.cpp
	$(CXX) $(CFLAGS) -lpthread -o $@ $^

run: clean execSan fuzz_pytorch_lightning.py
	./execSan ./fuzz_pytorch_lightning.py -dict=vuln.dict

clean:
	rm -f execSan /tmp/tripwire
