#!/bin/bash -eu

case $SANITIZER in
  address)   SAN=-fsanitize=address ;;
  undefined) SAN=-fsanitize=undefined ;;
esac

CFLAGS=$(echo "$CFLAGS" | sed 's/-f[no-]*sanitize[^ ]*//g')

cd $SRC/pypy/pypy/goal
CC=clang pypy ../../rpython/bin/rpython --opt=2 --shared --source

BUILD_DIR=$(dirname $(find /tmp/usession-py3.11-* -name 'Makefile' | head -1))
make -j$(nproc) -C $BUILD_DIR "CC=clang $SAN"
cp $BUILD_DIR/pypy3*-c $BUILD_DIR/libpypy3*-c.so .
ln -sf libpypy3.11-c.so libpypy3-c.so

export LD_LIBRARY_PATH=$SRC/pypy/pypy/goal
PYPY=$SRC/pypy/pypy/goal/pypy3.11-c

# Build fuzz targets
cd $SRC/pypy-fuzz
while read -r name; do
    CC=clang CFLAGS="$SAN" LDSHARED="clang -shared $SAN" $PYPY build_cffi_fuzz.py "$name"
    clang $SAN $CFLAGS -fsanitize=fuzzer-no-link fuzzer_stub.c ./_pypy_fuzz_${name}.so \
        -L$SRC/pypy/pypy/goal -lpypy3-c -Wl,-rpath,'$ORIGIN' \
        $LIB_FUZZING_ENGINE -rdynamic -ldl -o fuzzer-${name}

    cp fuzzer-${name} _pypy_fuzz_${name}.so fuzz_${name}.py $OUT/
    if [ -d "corp-${name}" ]; then
        zip -j "$OUT/fuzzer-${name}_seed_corpus.zip" corp-${name}/*
    fi
    if [ -f "dictionaries/fuzzer-${name}.dict" ]; then
        cp "dictionaries/fuzzer-${name}.dict" "$OUT/"
    fi
done < fuzz_targets.txt

cp $SRC/pypy/pypy/goal/libpypy3.11-c.so $OUT/libpypy3-c.so
cp ubsan_suppressions.txt $OUT/
cp -R $SRC/pypy/lib-python $OUT/
cp -R $SRC/pypy/lib_pypy $OUT/
