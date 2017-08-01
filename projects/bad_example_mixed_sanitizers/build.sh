#!/bin/bash -eu

# Enable multiple sanitizers because I can.
export CFLAGS="-O1 -fsanitize=address,undefined -fsanitize-coverage=trace-pc-guard,trace-cmp"
export CXXFLAGS="-O1 -fsanitize=address,undefined -fsanitize-coverage=trace-pc-guard,trace-cmp -stdlib=libc++"

./configure
make -j$(nproc) clean
make -j$(nproc) all

$CXX $CXXFLAGS -std=c++11 -I. \
    $SRC/zlib_uncompress_fuzzer.cc -o $OUT/zlib_uncompress_fuzzer \
    -lFuzzingEngine ./libz.a

#
# How to detect.
# 1) Get the following values:
#    ASAN_CALLS = `objdump -dC FUZZER | egrep "callq\s+[0-9a-f]+\s+<__asan" -c`
#    MSAN_CALLS = `objdump -dC FUZZER | egrep "callq\s+[0-9a-f]+\s+<__msan" -c`
#    UBSAN_CALLS = `objdump -dC FUZZER | egrep "callq\s+[0-9a-f]+\s+<__ubsan" -c`
#
# 2) If $SANITIZER == address, the following condition should be TRUE:
#    ASAN_CALLS > 1000 && MSAN_CALLS < 100 && UBSAN_CALLS < 250
#
# 3) If $SANITIZER == memory, the following condition should be TRUE:
#    ASAN_CALLS < 100 && MSAN_CALLS > 1000 && UBSAN_CALLS < 250
#
# 4) If $SANITIZER == undefined, the following condition should be TRUE:
#    ASAN_CALLS < 100 && MSAN_CALLS < 100 && UBSAN_CALLS > 250
#
# 5) If none of the conditions was TRUE, we got a bad build.
#
#    
# Examples to prove the threshold numbers.
#
# Values for "ASan + UBSan" build as specified above:
# $ objdump -dC zlib_uncompress_fuzzer | egrep "callq\s+[0-9a-f]+\s+<__asan" -c
# 18515
#
# $ objdump -dC zlib_uncompress_fuzzer | egrep "callq\s+[0-9a-f]+\s+<__msan" -c
# 0
#
# $ objdump -dC zlib_uncompress_fuzzer | egrep "callq\s+[0-9a-f]+\s+<__ubsan" -c
# 1914
#
#
# Values for valid ASan build:
# $ objdump -dC zlib_uncompress_fuzzer | egrep "callq\s+[0-9a-f]+\s+<__asan" -c
# 18366
# $ objdump -dC zlib_uncompress_fuzzer | egrep "callq\s+[0-9a-f]+\s+<__msan" -c
# 0
# $ objdump -dC zlib_uncompress_fuzzer | egrep "callq\s+[0-9a-f]+\s+<__ubsan" -c
# 160
#
#
# Values for valid MSan build:
# $ objdump -dC zlib_uncompress_fuzzer | egrep "callq\s+[0-9a-f]+\s+<__asan" -c
# 0
# $ objdump -dC zlib_uncompress_fuzzer | egrep "callq\s+[0-9a-f]+\s+<__msan" -c
# 36633
# $ objdump -dC zlib_uncompress_fuzzer | egrep "callq\s+[0-9a-f]+\s+<__ubsan" -c
# 160
#
#
# Values for valid UBSan build:
# $ objdump -dC zlib_uncompress_fuzzer | egrep "callq\s+[0-9a-f]+\s+<__asan" -c
# 0
# $ objdump -dC zlib_uncompress_fuzzer | egrep "callq\s+[0-9a-f]+\s+<__msan" -c
# 0
# $ objdump -dC zlib_uncompress_fuzzer | egrep "callq\s+[0-9a-f]+\s+<__ubsan" -c
# 439
#
#
# Values for other fuzzers:
#
# example, ASan  17629 ASan calls,     0 MSan calls, 160 UBSan calls.
# example, MSan:     0 ASan calls, 35960 MSan calls, 160 UBSan calls.
# example, UBSan:    0 ASan calls,     0 MSan calls, 373 UBSan calls.
#
# libteken, ASan: 18215 ASan calls,     0 MSan calls, 160 UBSan calls.
# libteken, MSan:     0 ASan calls, 36486 MSan calls, 160 UBSan calls.
# libteken, UBSan:    0 ASan calls,     0 MSan calls, 394 UBSan calls.
# 
# arduinojson, ASan: 17884 ASan calls,     0 MSan calls, 160 UBSan calls.
# arduinojson, MSan:     0 ASan calls, 36307 MSan calls, 160 UBSan calls.
# arduinojson, UBSan:    0 ASan calls,     0 MSan calls, 431 UBSan calls.
#
# Edge case, values for one of the biggest targets from libreoffice, 500+ MB.
# slkfuzzer, ASan: 1457330 ASan calls,     0 MSan calls, 160 UBSan calls.
#
#
#
