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

libnmap:  PoEs/python-libnmap-0.7.2/
	cp ./execSan.cpp ./vuln.dict ./PoEs/python-libnmap-0.7.2/
	(cd PoEs/python-libnmap-0.7.2/; \
	docker build . --tag python-libnmap; \
	docker run -t python-libnmap:latest)


clean:
	rm -f execSan /tmp/tripwire target
	(cd PoEs/python-libnmap-0.7.2/; \
	rm -rf execSan.cpp vuln.dict)
