#!/bin/bash
$CXX $CXXFLAGS -std=c++11 -g src/cxa_demangle.cpp -Iinclude fuzz/cxa_demangle_fuzzer.cpp -o $OUT/cxa_demangle_fuzzer  -lFuzzingEngine
