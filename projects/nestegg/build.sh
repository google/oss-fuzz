#!/bin/bash -eu

$CXX $CXXFLAGS -o $OUT/fuzz -I./include src/nestegg.c test/fuzz.cc -lFuzzingEngine

mkdir corpus/
cp -R testdata/*.webm corpus/
cp nestegg/test/media/*.webm corpus/
zip -rj0 $OUT/fuzz_seed_corpus.zip corpus/*.webm
