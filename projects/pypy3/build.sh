#!/bin/bash -eu

export ASAN_OPTIONS="detect_leaks=0:detect_stack_use_after_return=0"
ulimit -s 65536

case $SANITIZER in
  address)   SAN=-fsanitize=address ;;
  undefined) SAN=-fsanitize=undefined ;;
  *)         SAN="" ;;
esac

CFLAGS=$(echo "$CFLAGS" | sed 's/-f[no-]*sanitize[^ ]*//g')

export PYPY_INSTALL_PATH=$SRC/pypy-install
mkdir -p $PYPY_INSTALL_PATH

cd $SRC/pypy/pypy/goal
CC=clang pypy ../../rpython/bin/rpython --opt=2 --shared --source

BUILD_DIR=$(dirname $(find /tmp/usession-py3.11-* -name 'Makefile' | head -1))
make -j$(nproc) -C $BUILD_DIR "CC=clang $SAN"
ar rcs $BUILD_DIR/libpypy3-c.a $BUILD_DIR/*.o
cp $BUILD_DIR/pypy3*-c $BUILD_DIR/libpypy3*-c.so $BUILD_DIR/libpypy3-c.a .

# Package
cd $SRC/pypy
mkdir -p /tmp/pypy-pkg
CC=clang CFLAGS="" pypy pypy/tool/release/package.py \
    --archive-name=pypy-built \
    --targetdir=/tmp/pypy-pkg
tar xf /tmp/pypy-pkg/pypy-built.tar.bz2 -C $PYPY_INSTALL_PATH --strip-components=1
cp $SRC/pypy/pypy/goal/libpypy3*-c.so $PYPY_INSTALL_PATH/bin/
ln -sf libpypy3.11-c.so $PYPY_INSTALL_PATH/bin/libpypy3-c.so

export LD_LIBRARY_PATH=$PYPY_INSTALL_PATH/bin
PYPY=$PYPY_INSTALL_PATH/bin/pypy3

# Build fuzz targets
cd $SRC/pypy-fuzz
while read -r name; do
    CC=clang CFLAGS="$SAN" LDSHARED="clang -shared $SAN" $PYPY build_cffi_fuzz.py "$name"
    clang $SAN $CFLAGS -fsanitize=fuzzer-no-link fuzzer_stub.c ./_pypy_fuzz_${name}.so \
        -Wl,--start-group $SRC/pypy/pypy/goal/libpypy3-c.a -L$PYPY_INSTALL_PATH/bin -lpypy3-c -Wl,--end-group \
        $LIB_FUZZING_ENGINE -rdynamic -ldl -lpthread -lm -lffi -lz -lbz2 -lncursesw -ltinfo -lrt -lutil \
        -Wl,-rpath,'$ORIGIN' \
        -o fuzzer-${name}

    cp fuzzer-${name} _pypy_fuzz_${name}.so fuzz_${name}.py ubsan_suppressions.txt $OUT/
    cp $PYPY_INSTALL_PATH/bin/libpypy3.11-c.so $OUT/libpypy3-c.so
    if [ -d "corp-${name}" ]; then
        zip -j "$OUT/fuzzer-${name}_seed_corpus.zip" corp-${name}/*
    fi
    if [ -f "fuzzer-${name}.dict" ]; then
        cp "fuzzer-${name}.dict" "$OUT/"
    fi
done < fuzz_targets.txt

cp -R $PYPY_INSTALL_PATH $OUT/
