#!/bin/bash -eu

$CC $CFLAGS -c -I./include src/nestegg.c
$CXX $CXXFLAGS -o $OUT/fuzz -I./include nestegg.o test/fuzz.cc $LIB_FUZZING_ENGINE


mkdir corpus/
cp -R ../testdata/*.webm corpus/
cp test/media/*.webm corpus/
zip -rj0 $OUT/fuzz_seed_corpus.zip corpus/*.webm
