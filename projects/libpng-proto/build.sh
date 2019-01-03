#!/bin/bash

# build libpng using the upstream-provided build.sh.
# it will also build the vanilla (non-proto) fuzz target,
# but we discard it.
(cd libpng/ && contrib/oss-fuzz/build.sh && rm $OUT/*)

# Compile png_fuzz_proto.proto; should produce two files in genfiles/:
# png_fuzz_proto.pb.cc  png_fuzz_proto.pb.h
rm -rf genfiles && mkdir genfiles && LPM/external.protobuf/bin/protoc png_fuzz_proto.proto --cpp_out=genfiles

# compile the upstream-provided vanilla fuzz target
# but replace LLVMFuzzerTestOneInput with FuzzPNG so that
# png_proto_fuzzer_example.cc can call FuzzPNG from its own
# LLVMFuzzerTestOneInput.
$CXX $CXXFLAGS -c -DLLVMFuzzerTestOneInput=FuzzPNG libpng/contrib/oss-fuzz/libpng_read_fuzzer.cc -I libpng

# compile & link the rest
$CXX $CXXFLAGS png_proto_fuzzer_example.cc libpng_read_fuzzer.o genfiles/png_fuzz_proto.pb.cc \
  -I genfiles -I.  -I libprotobuf-mutator/  -I LPM/external.protobuf/include \
  -lz \
  LPM/src/libfuzzer/libprotobuf-mutator-libfuzzer.a \
  LPM/src/libprotobuf-mutator.a \
  LPM/external.protobuf/lib/libprotobuf.a \
  libpng/.libs/libpng16.a \
  $LIB_FUZZING_ENGINE \
  -o $OUT/png_proto_fuzzer_example

