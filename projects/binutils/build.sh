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

LIBS="../opcodes/libopcodes.a ../libctf/.libs/libctf.a ../bfd/libbfd.a ../zlib/libz.a ../libiberty/libiberty.a"
for i in fuzz_disassemble fuzz_bfd; do
    $CC $CFLAGS -I ../include -I ../bfd -I ../opcodes -c $i.c -o $i.o
    $CXX $CXXFLAGS $i.o -o $OUT/$i $LIB_FUZZING_ENGINE -Wl,--start-group ${LIBS} -Wl,--end-group
done
# TODO build corpuses

# Now compile the src/binutils fuzzers
cd ../binutils

# Compile the fuzzers.
# The general strategy is to remove main functions such that the fuzzer (which has its own main)
# can link against the code.

# Patching
# First do readelf. We do this by changing readelf.c to readelf.h - the others will be changed
# to fuzz_readelf.h where readelf is their respective name. The reason it's different for readelf
# is because readelf does not have a header file so we can use readelf.h instead, and changing it
# might cause an annoyance on monorail since bugs will be relocated as the files will be different.
cp ../../fuzz_readelf.c .
sed 's/main (int argc/old_main (int argc, char **argv);\nint old_main (int argc/' readelf.c >> readelf.h

# Patch the remainders
for i in objdump nm; do
    cp ../../fuzz_$i.c .
    sed 's/main (int argc/old_main (int argc, char **argv);\nint old_main (int argc/' $i.c >> fuzz_$i.h
done

# Compile
for i in objdump readelf nm; do
    $CC $CFLAGS -DHAVE_CONFIG_H -DOBJDUMP_PRIVATE_VECTORS="" -I. -I../bfd -I./../bfd -I./../include \
      -I./../zlib -DLOCALEDIR="\"/usr/local/share/locale\"" \
      -Dbin_dummy_emulation=bin_vanilla_emulation -W -Wall -MT \
      fuzz_$i.o -MD -MP -c -o fuzz_$i.o fuzz_$i.c
done

# Link the files
# Only link if they exist
if ([ -f dwarf.o ] && [ -f elfcomm.o ] && [ -f version.o ]); then
  ## Readelf
  $CXX $CXXFLAGS $LIB_FUZZING_ENGINE -W -Wall -I./../zlib \
    -o $OUT/fuzz_readelf fuzz_readelf.o \
    version.o unwind-ia64.o dwarf.o elfcomm.o \
    ../libctf/.libs/libctf-nobfd.a -L/src/binutils-gdb/zlib -lz ../libiberty/libiberty.a

  # Link objdump fuzzer
  OBJS="dwarf.o prdbg.o rddbg.o unwind-ia64.o debug.o stabs.o rdcoff.o bucomm.o version.o filemode.o elfcomm.o od-xcoff.o"
  $CXX $CXXFLAGS $LIB_FUZZING_ENGINE -I./../zlib \
    -o $OUT/fuzz_objdump fuzz_objdump.o ${OBJS} \
    -Wl,--start-group ${LIBS} -Wl,--end-group

  # Link nm fuzzer
  $CXX $CXXFLAGS $LIB_FUZZING_ENGINE -I./../zlib \
    -o $OUT/fuzz_nm fuzz_nm.o bucomm.o version.o filemode.o \
    -Wl,--start-group ${LIBS} -Wl,--end-group
fi

# Set up seed corpus for readelf in the form of a single ELF file.
zip fuzz_readelf_seed_corpus.zip /src/fuzz_readelf_seed_corpus/simple_elf
mv fuzz_readelf_seed_corpus.zip $OUT/

# Copy over the options file
cp $SRC/fuzz_readelf.options $OUT/fuzz_readelf.options
