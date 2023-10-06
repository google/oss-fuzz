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
	    --disable-libbacktrace --disable-gas --disable-ld --disable-werror \
      --enable-targets=all
make clean
make MAKEINFO=true && true


# Make fuzzer directory
mkdir fuzz
cp ../fuzz_*.c fuzz/
cd fuzz

LIBS="../opcodes/libopcodes.a ../libctf/.libs/libctf.a ../bfd/.libs/libbfd.a ../zlib/libz.a ../libsframe/.libs/libsframe.a ../libiberty/libiberty.a"
for i in fuzz_disassemble fuzz_bfd fuzz_bfd_ext; do
    $CC $CFLAGS -I ../include -I ../bfd -I ../opcodes -c $i.c -o $i.o
    $CXX $CXXFLAGS $i.o -o $OUT/$i $LIB_FUZZING_ENGINE -Wl,--start-group ${LIBS} -Wl,--end-group
done

# Build targeted disassembly fuzzers
if [ -n "${OSS_FUZZ_CI-}" ]
then
  echo "Skipping specialised disassembly fuzzers in CI to reduce build time"
else
  for ARCH_TARGET in bfd_arch_arm bfd_arch_mips bfd_arch_i386 bfd_arch_arc bfd_arch_csky bfd_arch_mep; do
      $CC $CFLAGS -I ../include -I ../bfd -I ../opcodes -c fuzz_disas_ext.c -DFUZZ_TARGET_ARCH=$ARCH_TARGET \
        -o fuzz_disas_ext-$ARCH_TARGET.o
      $CXX $CXXFLAGS fuzz_disas_ext-$ARCH_TARGET.o -o $OUT/fuzz_disas_ext-$ARCH_TARGET $LIB_FUZZING_ENGINE \
        -Wl,--start-group ${LIBS} -Wl,--end-group
  done
fi

# Now compile the src/binutils fuzzers
cd ../binutils

# Compile the fuzzers.
# The general strategy is to remove main functions such that the fuzzer (which has its own main)
# can link against the code.

#
# Patching
#
# First do readelf. We do this by changing readelf.c to readelf.h - the others will be changed
# to fuzz_readelf.h where readelf is their respective name. The reason it's different for readelf
# is because readelf does not have a header file so we can use readelf.h instead, and changing it
# might cause an annoyance on monorail since bugs will be relocated as the files will be different.
cp ../../fuzz_*.c .
sed 's/main (int argc/old_main (int argc, char **argv);\nint old_main (int argc/' readelf.c >> readelf.h

# Special handling of dlltool
sed 's/main (int ac/old_main32 (int ac, char **av);\nint old_main32 (int ac/' dlltool.c > fuzz_dlltool.h
sed -i 's/copy_mian/copy_main/g' fuzz_dlltool.h

# Patch the rest
for i in objdump nm objcopy windres strings addr2line; do
    sed -i 's/strip_main/strip_mian/g' $i.c
    sed -i 's/copy_main/copy_mian/g' $i.c
    sed 's/main (int argc/old_main32 (int argc, char **argv);\nint old_main32 (int argc/' $i.c > fuzz_$i.h
    sed -i 's/copy_mian/copy_main/g' fuzz_$i.h
done

#
# Compile fuzzers
#
fuzz_compile () {
  src=$1
  dst=$2
  extraflags=$3
  $CC $CFLAGS ${extraflags} -DHAVE_CONFIG_H -DOBJDUMP_PRIVATE_VECTORS="" -I. -I../bfd -I./../bfd -I./../include \
    -I./../zlib -DLOCALEDIR="\"/usr/local/share/locale\"" \
    -Dbin_dummy_emulation=bin_vanilla_emulation -W -Wall -MT \
    fuzz_$dst.o -MD -MP -c -o fuzz_$dst.o fuzz_$src.c
}
for i in objdump readelf nm objcopy windres ranlib_simulation strings addr2line dwarf; do
  fuzz_compile $i $i ""
done

# Fuzzers that need additional flags
fuzz_compile dlltool dlltool "-DDLLTOOL_I386 -DDLLTOOL_DEFAULT_I386"
fuzz_compile objdump objdump_safe "-DOBJDUMP_SAFE"
fuzz_compile readelf readelf_pef "-DREADELF_TARGETED=\"pef\""
fuzz_compile readelf readelf_elf32_bigarm "-DREADELF_TARGETED=\"elf32-bigarm\""
fuzz_compile readelf readelf_elf32_littlearm "-DREADELF_TARGETED=\"elf32-littlearm\""
fuzz_compile readelf readelf_elf64_mmix "-DREADELF_TARGETED=\"elf64-mmix\""
fuzz_compile readelf readelf_elf32_csky "-DREADELF_TARGETED=\"elf32-csky\""

#
# Link fuzzers
#
# Link the files, but only if everything went well, which we verify by checking
# the presence of some object files.
LINK_LIBS="-Wl,--start-group ${LIBS} -Wl,--end-group"
OBJ1="bucomm.o version.o filemode.o"
OBJ2="version.o unwind-ia64.o dwarf.o elfcomm.o demanguse.o"
OBJ3="dwarf.o prdbg.o rddbg.o unwind-ia64.o debug.o stabs.o rdcoff.o bucomm.o version.o filemode.o elfcomm.o od-xcoff.o demanguse.o"

declare -A fl
fl["readelf"]=${OBJ2}
fl["readelf_pef"]=${OBJ2}
fl["readelf_elf32_bigarm"]=${OBJ2}
fl["readelf_elf32_littlearm"]=${OBJ2}
fl["readelf_elf64_mmix"]=${OBJ2}
fl["readelf_elf32_csky"]=${OBJ2}
fl["objdump"]=${OBJ3}
fl["objdump_safe"]=${OBJ3}
fl["dwarf"]=${OBJ3}
fl["addr2line"]=${OBJ1}
fl["objcopy"]="is-strip.o rename.o rddbg.o debug.o stabs.o rdcoff.o wrstabs.o ${OBJ1}"
fl["nm"]="${OBJ1} demanguse.o"
fl["dlltool"]="defparse.o deflex.o ${OBJ1}"
fl["windres"]="resrc.o rescoff.o resbin.o rcparse.o rclex.o winduni.o resres.o ${OBJ1}"
fl["ranlib_simulation"]=" "
fl["strings"]=${OBJ1}
for fuzzer in ${!fl[@]}; do
  $CXX $CXXFLAGS $LIB_FUZZING_ENGINE -W -Wall -I./../zlib \
    -o $OUT/fuzz_${fuzzer} fuzz_${fuzzer}.o \
    ${fl[${fuzzer}]} ${LINK_LIBS}
done

# Build GAS fuzzer. Will keep this here in case GAS fuzzer is used in the future.
if [ "$FUZZING_ENGINE" != "afl" ]
then
  cd ../gas
  ./configure
  make
  sed 's/main (int argc/old_main32 (int argc, char **argv);\nint old_main32 (int argc/' as.c > fuzz_as.h
  rm as.o || true
  ar r libar.a *.o

  $CC $CFLAGS -DHAVE_CONFIG_H -I.  -I. -I. -I../bfd -I./config -I./../include -I./.. -I./../bfd \
      -DLOCALEDIR="\"/usr/local/share/locale\"" -I./../zlib -c $SRC/fuzz_as.c -o fuzz_as.o
  $CXX $CXXFLAGS $LIB_FUZZING_ENGINE -I./../zlib -o $OUT/fuzz_as ./fuzz_as.o \
      libar.a config/tc-i386.o config/obj-elf.o config/atof-ieee.o  \
      ../opcodes/.libs/libopcodes.a ../bfd/.libs/libbfd.a \
      -L/src/binutils-gdb/zlib ../libsframe/.libs/libsframe.a ../libiberty/libiberty.a -lz
fi

# Copy seeds out
for fuzzname in readelf_pef readelf_elf32_csky readelf_elf64_mmix readelf_elf32_littlearm readelf_elf32_bigarm objdump objdump_safe nm objcopy bdf windres addr2line dwarf; do
  cp $SRC/binary-samples/oss-fuzz-binutils/general_seeds.zip $OUT/fuzz_${fuzzname}_seed_corpus.zip
done
# Seed targeted the pef file format
cp $SRC/binary-samples/oss-fuzz-binutils/fuzz_bfd_ext_seed_corpus.zip $OUT/fuzz_bfd_ext_seed_corpus.zip

# Copy options files
for ft in readelf readelf_pef readelf_elf32_csky readelf_elf64_mmix readelf_elf32_littlearm readelf_elf32_bigarm objcopy objdump dlltool disas_ext-bfd_arch_csky nm as windres objdump_safe ranlib_simulation addr2line dwarf; do
  echo "[libfuzzer]" > $OUT/fuzz_${ft}.options
  echo "detect_leaks=0" >> $OUT/fuzz_${ft}.options
done
