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


# Due to a bug in AFLPP that occurs *sometimes* we continue only if we have the
# libraries that we need
if ([ -f ./libctf/.libs/libctf.a ]); then
  # Make fuzzer directory
  mkdir fuzz
  cp ../fuzz_*.c fuzz/
  cd fuzz

  LIBS="../opcodes/libopcodes.a ../libctf/.libs/libctf.a ../bfd/libbfd.a ../zlib/libz.a ../libiberty/libiberty.a"
  for i in fuzz_disassemble fuzz_bfd fuzz_bfd_ext; do
      $CC $CFLAGS -I ../include -I ../bfd -I ../opcodes -c $i.c -o $i.o
      $CXX $CXXFLAGS $i.o -o $OUT/$i $LIB_FUZZING_ENGINE -Wl,--start-group ${LIBS} -Wl,--end-group
  done

  # Build targeted disassembly fuzzers
  if [ -n "${OSS_FUZZ_CI-}" ]
  then
    echo "Skipping specialised disassembly fuzzers in CI"
  else
    for ARCH_TARGET in bfd_arch_arm bfd_arch_mips bfd_arch_i386 bfd_arch_arc bfd_arch_csky bfd_arch_mep; do
        $CC $CFLAGS -I ../include -I ../bfd -I ../opcodes -c fuzz_disas_ext.c -DFUZZ_TARGET_ARCH=$ARCH_TARGET \
          -o fuzz_disas_ext-$ARCH_TARGET.o
        $CXX $CXXFLAGS fuzz_disas_ext-$ARCH_TARGET.o -o $OUT/fuzz_disas_ext-$ARCH_TARGET $LIB_FUZZING_ENGINE \
          -Wl,--start-group ${LIBS} -Wl,--end-group
    done
  fi

  # TODO build corpuses

  # Now compile the src/binutils fuzzers
  cd ../binutils

  # Compile the fuzzers.
  # The general strategy is to remove main functions such that the fuzzer (which has its own main)
  # can link against the code.

  # Copy over precondition files
  cp $SRC/binutils-preconditions/*.h .

  # Patching
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

  # Compile all fuzzers
  for i in objdump readelf nm objcopy windres ranlib_simulation strings addr2line; do
      $CC $CFLAGS -DHAVE_CONFIG_H -DOBJDUMP_PRIVATE_VECTORS="" -I. -I../bfd -I./../bfd -I./../include \
        -I./../zlib -DLOCALEDIR="\"/usr/local/share/locale\"" \
        -Dbin_dummy_emulation=bin_vanilla_emulation -W -Wall -MT \
        fuzz_$i.o -MD -MP -c -o fuzz_$i.o fuzz_$i.c
  done

  # fuzz_dwarf
  $CC $CFLAGS -DHAVE_CONFIG_H -DOBJDUMP_PRIVATE_VECTORS="" -I. -I../bfd -I./../bfd -I./../include \
        -I./../zlib -DLOCALEDIR="\"/usr/local/share/locale\"" \
        -Dbin_dummy_emulation=bin_vanilla_emulation -W -Wall -MT \
        fuzz_dwarf.o -MD -MP -c -o fuzz_dwarf.o fuzz_dwarf.c

  # Special handling of dlltool
  for i in dlltool; do
      $CC $CFLAGS -DHAVE_CONFIG_H -DOBJDUMP_PRIVATE_VECTORS="" -I. -I../bfd -I./../bfd -I./../include \
        -I./../zlib -DLOCALEDIR="\"/usr/local/share/locale\"" \
        -DDLLTOOL_I386 -DDLLTOOL_DEFAULT_I386 -Dbin_dummy_emulation=bin_vanilla_emulation -W -Wall -MT \
        fuzz_$i.o -MD -MP -c -o fuzz_$i.o fuzz_$i.c
  done


  # Compile a special version of objdump that limits the amount
  # of calls to bfd_fatal.
  $CC $CFLAGS -DHAVE_CONFIG_H -DOBJDUMP_PRIVATE_VECTORS="" -DOBJDUMP_SAFE -I. -I../bfd -I./../bfd -I./../include \
    -I./../zlib -DLOCALEDIR="\"/usr/local/share/locale\"" \
    -Dbin_dummy_emulation=bin_vanilla_emulation -W -Wall -MT \
    fuzz_objdump_safe.o -MD -MP -c -o fuzz_objdump_safe.o fuzz_objdump.c

  # Targeted version of readelf. We try with a single target for now, but
  # this should be revised at a later stage.
  $CC $CFLAGS -DHAVE_CONFIG_H -DOBJDUMP_PRIVATE_VECTORS="" -DREADELF_TARGETED -I. -I../bfd -I./../bfd -I./../include \
    -I./../zlib -DLOCALEDIR="\"/usr/local/share/locale\"" \
    -Dbin_dummy_emulation=bin_vanilla_emulation -W -Wall -MT \
    -MD -MP -c -o fuzz_readelf_pef.o fuzz_readelf.c


  # Link the files, but only if everything went well, which we verify by checking
  # the presence of some object files.
  if ([ -f dwarf.o ] && [ -f elfcomm.o ] && [ -f version.o ]); then
    LINK_LIBS="-Wl,--start-group ${LIBS} -Wl,--end-group"
    ## Readelf
    OBJS="version.o unwind-ia64.o dwarf.o elfcomm.o demanguse.o"
    $CXX $CXXFLAGS $LIB_FUZZING_ENGINE -W -Wall -I./../zlib \
      -o $OUT/fuzz_readelf fuzz_readelf.o \
      ${OBJS} \
      ${LINK_LIBS}

    # Targeted readelf fuzzer
    $CXX $CXXFLAGS $LIB_FUZZING_ENGINE -W -Wall -I./../zlib \
      -o $OUT/fuzz_readelf_pef fuzz_readelf_pef.o \
      ${OBJS} \
      ${LINK_LIBS}

    # Link objdump fuzzer
    OBJS="dwarf.o prdbg.o rddbg.o unwind-ia64.o debug.o stabs.o rdcoff.o bucomm.o version.o filemode.o elfcomm.o od-xcoff.o demanguse.o"
    $CXX $CXXFLAGS $LIB_FUZZING_ENGINE -I./../zlib \
      -o $OUT/fuzz_objdump fuzz_objdump.o ${OBJS} ${LINK_LIBS}

    # Link safe objdump fuzzer
    $CXX $CXXFLAGS $LIB_FUZZING_ENGINE -I./../zlib \
      -o $OUT/fuzz_objdump_safe fuzz_objdump_safe.o ${OBJS} ${LINK_LIBS}

    # Link dwarf fuzzer
    OBJS="dwarf.o prdbg.o rddbg.o unwind-ia64.o debug.o stabs.o rdcoff.o bucomm.o version.o filemode.o elfcomm.o od-xcoff.o demanguse.o"
    $CXX $CXXFLAGS $LIB_FUZZING_ENGINE -I./../zlib \
      -o $OUT/fuzz_dwarf fuzz_dwarf.o ${OBJS} ${LINK_LIBS}

    # link addr2line fuzzer
    OBJS="bucomm.o version.o filemode.o "
    $CXX $CXXFLAGS $LIB_FUZZING_ENGINE -I./../zlib \
      -o $OUT/fuzz_addr2line fuzz_addr2line.o ${OBJS} ${LINK_LIBS}

    # link objcopy fuzzer
    OBJS="is-strip.o rename.o rddbg.o debug.o stabs.o rdcoff.o wrstabs.o bucomm.o version.o filemode.o"
    $CXX $CXXFLAGS $LIB_FUZZING_ENGINE -I./../zlib \
      -o $OUT/fuzz_objcopy fuzz_objcopy.o ${OBJS} ${LINK_LIBS}

    # Link nm fuzzer
    OBJS="bucomm.o version.o filemode.o demanguse.o"
    $CXX $CXXFLAGS $LIB_FUZZING_ENGINE -I./../zlib \
      -o $OUT/fuzz_nm fuzz_nm.o ${OBJS} ${LINK_LIBS}

    # link dlltool fuzzer
    OBJS="defparse.o deflex.o bucomm.o version.o filemode.o"
    $CXX $CXXFLAGS $LIB_FUZZING_ENGINE -I./../zlib \
      -o $OUT/fuzz_dlltool fuzz_dlltool.o ${OBJS} ${LINK_LIBS}

    OBJS="resrc.o rescoff.o resbin.o rcparse.o rclex.o winduni.o resres.o bucomm.o version.o filemode.o"
    $CXX $CXXFLAGS $LIB_FUZZING_ENGINE -I./../zlib \
      -o $OUT/fuzz_windres fuzz_windres.o ${OBJS} ${LINK_LIBS}

    OBJS=""
    $CXX $CXXFLAGS $LIB_FUZZING_ENGINE -I./../zlib \
      -o $OUT/fuzz_ranlib_simulation fuzz_ranlib_simulation.o ${OBJS} ${LINK_LIBS}

    OBJS="bucomm.o version.o filemode.o"
    $CXX $CXXFLAGS $LIB_FUZZING_ENGINE -I./../zlib \
      -o $OUT/fuzz_strings fuzz_strings.o ${OBJS} ${LINK_LIBS}
  fi 
  # Build GAS fuzzer. Will keep this here in case GAS fuzzer is used in the future.
  if [ "$FUZZING_ENGINE" != 'afl' ]; then
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
        -L/src/binutils-gdb/zlib ../libiberty/libiberty.a -lz
  fi

  # BUILD SEEDS
  # Set up seed corpus for readelf in the form of a single ELF file.
  # Assuming all went well then we can simply create a fuzzer based on
  # the object files in the binutils directory.
  cd $SRC/
  mkdir corp
  cp $SRC/binutils-gdb/binutils/*.o ./corp/

  git clone https://github.com/DavidKorczynski/binary-samples $SRC/binary-samples
  cp $SRC/binary-samples/elf* $SRC/corp
  cp $SRC/binary-samples/Mach* $SRC/corp
  cp $SRC/binary-samples/pe* $SRC/corp
  cp $SRC/binary-samples/lib* $SRC/corp

  # Create a simple archive
  mkdir $SRC/tmp_archive
  cp $SRC/binutils-gdb/binutils/rename.o $SRC/tmp_archive/
  cp $SRC/binutils-gdb/binutils/is-ranlib.o $SRC/tmp_archive/
  cp $SRC/binutils-gdb/binutils/not-strip.o $SRC/tmp_archive/
  ar cr $SRC/seed_archive.a $SRC/tmp_archive/*.o
  mv $SRC/seed_archive.a ./corp/seed_archive.a

  # Zip the folder together as OSS-Fuzz expects the seed corpus as ZIP, and
  # then copy the folder around to various fuzzers.
  zip -r -j $OUT/fuzz_readelf_seed_corpus.zip $SRC/corp
  cp $OUT/fuzz_readelf_seed_corpus.zip $OUT/fuzz_readelf_pef_seed_corpus.zip
  cp $OUT/fuzz_readelf_seed_corpus.zip $OUT/fuzz_objdump_seed_corpus.zip
  cp $OUT/fuzz_readelf_seed_corpus.zip $OUT/fuzz_objdump_safe_seed_corpus.zip
  cp $OUT/fuzz_readelf_seed_corpus.zip $OUT/fuzz_nm_seed_corpus.zip
  cp $OUT/fuzz_readelf_seed_corpus.zip $OUT/fuzz_objcopy_seed_corpus.zip
  cp $OUT/fuzz_readelf_seed_corpus.zip $OUT/fuzz_bdf_seed_corpus.zip
  cp $OUT/fuzz_readelf_seed_corpus.zip $OUT/fuzz_windres_seed_corpus.zip
  cp $OUT/fuzz_readelf_seed_corpus.zip $OUT/fuzz_addr2line_seed_corpus.zip
  cp $OUT/fuzz_readelf_seed_corpus.zip $OUT/fuzz_dwarf_seed_corpus.zip

  # Seed targeted the pef file format
  mkdir $SRC/bfd_ext_seeds
  echo "Joy!peffAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" >> $SRC/bfd_ext_seeds/seed1
  zip -r $OUT/fuzz_bfd_ext_seed_corpus.zip $SRC/bfd_ext_seeds/

  # Copy options files
  for ft in readelf readelf_pef objcopy objdump dlltool disas_ext-bfd_arch_csky nm as windres objdump_safe ranlib_simulation addr2line dwarf; do
    echo "[libfuzzer]" > $OUT/fuzz_${ft}.options
    echo "detect_leaks=0" >> $OUT/fuzz_${ft}.options
  done
fi
