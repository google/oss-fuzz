.POSIX:
CXX     = clang++
CFLAGS = -std=c++17 -Wall -Wextra -O3 -g3 -Werror


all: SystemSan target target_file target_dns target_evil_link

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

target_evil_link: target_evil_link.cpp
	$(CXX) $(CFLAGS) -fsanitize=address,fuzzer -o $@ $^

test:  all vuln.dict
	./SystemSan ./target -dict=vuln.dict
	./SystemSan ./target_file -dict=vuln.dict
	./SystemSan ./target_dns -dict=vuln.dict

pytorch-lightning-1.5.10:
	cp SystemSan.cpp PoEs/pytorch-lightning-1.5.10/; \
	cd PoEs/pytorch-lightning-1.5.10/; \
	docker build . --tag syssan_pytorch-lightning; \
	docker run -t systemsan_pytorch-lightning:latest;

node-shell-quote-v1.7.3:
	cp SystemSan.cpp PoEs/node-shell-quote-v1.7.3/; \
	cd PoEs/node-shell-quote-v1.7.3/; \
	docker build . --tag systemsan_node-shell-quote; \
	docker run -t systemsan_node-shell-quote:latest;

clean:
	rm -f SystemSan /tmp/tripwire target target_file target_dns target_evil_link
