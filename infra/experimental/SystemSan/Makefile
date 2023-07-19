.POSIX:
CXX     = clang++
CFLAGS = -std=c++17 -Wall -Wextra -O3 -g3 -Werror

define test_fuzzer
	timeout 20s ./SystemSan './$(1)' -dict=vuln.dict 2>&1 | grep -q --text '===BUG DETECTED: $(2)==='
endef

all: SystemSan target target_file target_dns

SystemSan: SystemSan.cpp inspect_dns.cpp inspect_utils.cpp
	$(CXX) $(CFLAGS) -lpthread -o $@ $^

# Needs atheris.
python-test: all
	./SystemSan python shell_injection_poc_fuzzer.py

target: target.cpp
	$(CXX) $(CFLAGS) -fsanitize=address,fuzzer -o $@ $^

target_file: target_file.cpp
	$(CXX) $(CFLAGS) -fsanitize=address,fuzzer -o $@ $^

target_dns: target_dns.cpp
	$(CXX) $(CFLAGS) -fsanitize=address,fuzzer -o $@ $^

test:  all vuln.dict
	$(call test_fuzzer,target,Shell corruption)
	$(call test_fuzzer,target_dns,Arbitrary domain name resolution)
	$(call test_fuzzer,target_file,Arbitrary file open)

pytorch-lightning-1.5.10:
	cp SystemSan.cpp inspect_*.* PoEs/pytorch-lightning-1.5.10/; \
	cd PoEs/pytorch-lightning-1.5.10/; \
	docker build . --tag systemsan_pytorch-lightning; \
	docker run -it systemsan_pytorch-lightning:latest;

node-shell-quote-v1.7.3:
	cp SystemSan.cpp inspect_*.* PoEs/node-shell-quote-v1.7.3/; \
	cd PoEs/node-shell-quote-v1.7.3/; \
	docker build . --tag systemsan_node-shell-quote; \
	docker run -t systemsan_node-shell-quote:latest;

clean:
	rm -f SystemSan /tmp/tripwire target target_file target_dns
