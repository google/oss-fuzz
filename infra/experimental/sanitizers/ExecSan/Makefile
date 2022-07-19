.POSIX:
CXX     = clang++
CFLAGS = -std=c++17 -Wall -Wextra -O3 -g3

all: clean execSan target

execSan: execSan.cpp
	$(CXX) $(CFLAGS) -lpthread -o $@ $^

target: target.cpp
	$(CXX) $(CFLAGS) -fsanitize=address,fuzzer -o $@ $^

test:  all vuln.dict
	./execSan ./target -dict=vuln.dict

pytorch-lightning-1.5.10:
	cp execSan.cpp PoEs/pytorch-lightning-1.5.10/; \
	cd PoEs/pytorch-lightning-1.5.10/; \
	docker build . --tag execsan_pytorch-lightning; \
	docker run -t execsan_pytorch-lightning:latest;

node-shell-quote-v1.7.3:
	cp execSan.cpp PoEs/node-shell-quote-v1.7.3/; \
	cd PoEs/node-shell-quote-v1.7.3/; \
	docker build . --tag execsan_node-shell-quote; \
	docker run -t execsan_node-shell-quote:latest;

clean:
	rm -f execSan /tmp/tripwire target
