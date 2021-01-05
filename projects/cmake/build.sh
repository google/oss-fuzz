#!/bin/bash -eu
# Build CMake
mkdir build-dir && cd build-dir
../bootstrap && make -j$(nproc)


# Build fuzzers
cd ../Tests/Fuzzing
$CXX $CXXFLAGS 	-I../../Source \
		-I../../build-dir/Source \
		-c xml_parser_fuzzer.cc \
		-o xml_parser_fuzzer.o 


export cmexpat_dir="${SRC}/CMake/build-dir/Utilities/cmexpat/CMakeFiles/cmexpat.dir/lib"
$CXX $CXXFLAGS $LIB_FUZZING_ENGINE \
		xml_parser_fuzzer.o -o $OUT/xml_parser_fuzzer \
		../../build-dir/Source/CMakeFiles/CMakeLib.dir/cmXMLParser.cxx.o \
		$cmexpat_dir/xmlparse.c.o \
		$cmexpat_dir/xmlrole.c.o \
		$cmexpat_dir/xmltok.c.o	


# Build seed corpus
zip $OUT/xml_parser_fuzzer_seed_corpus.zip $SRC/fuzzing-corpus/xml/test.xml
