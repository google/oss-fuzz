#!/bin/bash -eu
# Copyright 2019 Google Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
################################################################################

# build project
if [ "$SANITIZER" = undefined ]; then
    export CFLAGS="$CFLAGS -fno-sanitize=unsigned-integer-overflow"
    export CXXFLAGS="$CXXFLAGS -fno-sanitize=unsigned-integer-overflow"
fi
cd binutils-gdb

# Comment out the lines of logging to stderror from elfcomm.c
# This is to make it nicer to read the output of libfuzzer.
cd binutils
sed -i 's/vfprintf (stderr/\/\//' elfcomm.c
sed -i 's/fprintf (stderr/\/\//' elfcomm.c
cd ../

./configure --disable-gdb --disable-gdbserver --disable-gdbsupport \
	    --disable-libdecnumber --disable-readline --disable-sim \
	    --enable-targets=all --disable-werror
make MAKEINFO=true && true

# Make fuzzer directory
mkdir fuzz
cp ../fuzz_*.c fuzz/
cd fuzz

for i in fuzz_disassemble fuzz_bfd; do
    $CC $CFLAGS -I ../include -I ../bfd -I ../opcodes -c $i.c -o $i.o
    $CXX $CXXFLAGS $i.o -o $OUT/$i $LIB_FUZZING_ENGINE ../opcodes/libopcodes.a ../bfd/libbfd.a ../libiberty/libiberty.a ../zlib/libz.a
done
# TODO build corpuses

# Now compile the src/binutils fuzzers
cd ../binutils

# First copy the fuzzers, modify applications and copile object files
for i in readelf; do
    cp ../../fuzz_$i.c .

    # Modify main functions so we dont have them anymore
    sed 's/main (int argc/old_main (int argc, char **argv);\nint old_main (int argc/' $i.c >> $i.h

    # Compile object file
    $CC $CFLAGS -DHAVE_CONFIG_H -I. -I../bfd -I./../bfd -I./../include -I./../zlib -DLOCALEDIR="\"/usr/local/share/locale\"" -Dbin_dummy_emulation=bin_vanilla_emulation -W -Wall -MT fuzz_$i.o -MD -MP -c -o fuzz_$i.o fuzz_$i.c
done

# Link the files
# Only link if they exist
if ([ -f dwarf.o ] && [ -f elfcomm.o ] && [ -f version.o ]); then
  ## Readelf
  $CXX $CXXFLAGS $LIB_FUZZING_ENGINE -W -Wall -I./../zlib -o fuzz_readelf fuzz_readelf.o version.o unwind-ia64.o dwarf.o elfcomm.o ../libctf/.libs/libctf-nobfd.a -L/src/binutils-gdb/zlib -lz ../libiberty/libiberty.a 
  mv fuzz_readelf $OUT/fuzz_readelf

  ### Set up seed corpus for readelf in the form of a single ELF file. 
  zip fuzz_readelf_seed_corpus.zip /src/fuzz_readelf_seed_corpus/simple_elf
  mv fuzz_readelf_seed_corpus.zip $OUT/ 

  ## Copy over the options file
  cp $SRC/fuzz_readelf.options $OUT/fuzz_readelf.options
fi
