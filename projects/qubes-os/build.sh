#!/bin/bash

export BACKEND_VMM=xen


cd $SRC/qubes-os/linux-utils/
git checkout origin/fuzz

cd qrexec-lib

$CC $CFLAGS -c ioall.c
$CC $CFLAGS -c copy-file.c
$CC $CFLAGS -c crc32.c
$CC $CFLAGS -c pack.c
$CC $CFLAGS -c unpack.c
ar rcs libqubes-rpc-filecopy.a ioall.o copy-file.o crc32.o unpack.o pack.o

$CXX $CXXFLAGS -o $OUT/fuzzer-qubes-rpc-filecopy -I. -I./fuzzer fuzzer/fuzzer.cc -lFuzzingEngine libqubes-rpc-filecopy.a

