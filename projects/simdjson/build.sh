#!/bin/bash -eu
# Build simdjson using its amalgamated single-file distribution.

cd $SRC/simdjson

# Generate the amalgamated single-file header + source if not present.
if [ ! -f singleheader/simdjson.h ]; then
    cmake -S . -B build_amalgamate \
        -DSIMDJSON_JUST_LIBRARY=ON \
        -DCMAKE_CXX_COMPILER="$CXX" \
        -DCMAKE_CXX_FLAGS="$CXXFLAGS"
    cmake --build build_amalgamate --target amalgamate 2>/dev/null || true
fi

# The singleheader directory should now contain simdjson.h / simdjson.cpp.
SRC_DIR=$SRC/simdjson

# Compile the simdjson amalgamate source.
$CXX $CXXFLAGS -std=c++17 \
    -c singleheader/simdjson.cpp \
    -I singleheader \
    -o simdjson.o

# Build fuzz target.
$CXX $CXXFLAGS -std=c++17 \
    $SRC/simdjson_fuzzer.cc \
    simdjson.o \
    -I singleheader \
    $LIB_FUZZING_ENGINE \
    -o $OUT/simdjson_fuzzer
