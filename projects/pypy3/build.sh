#!/bin/bash -eu

export ASAN_OPTIONS="detect_leaks=0"

case $SANITIZER in
  address)   SAN=-fsanitize=address ;;
  undefined) SAN=-fsanitize=undefined ;;
  *)         SAN="" ;;
esac

# Funky way to work around RPython
cat > /usr/local/bin/pypy-cc <<EOF
#!/bin/sh
exec clang $SAN "\$@"
EOF
chmod +x /usr/local/bin/pypy-cc

export CC=pypy-cc
CFLAGS=$(echo "$CFLAGS" | sed 's/-f[no-]*sanitize[^ ]*//g')

export PYPY_INSTALL_PATH=$SRC/pypy-install
mkdir -p $PYPY_INSTALL_PATH

cd $SRC/pypy/pypy/goal
pypy ../../rpython/bin/rpython --opt=2 --shared

cd $SRC/pypy
mkdir -p /tmp/pypy-pkg
pypy pypy/tool/release/package.py \
    --archive-name=pypy-built \
    --targetdir=/tmp/pypy-pkg
tar xf /tmp/pypy-pkg/pypy-built.tar.bz2 -C $PYPY_INSTALL_PATH --strip-components=1
ln -sf libpypy3.11-c.so $PYPY_INSTALL_PATH/bin/libpypy3-c.so

PYPY=$PYPY_INSTALL_PATH/bin/pypy3

cd $SRC/pypy-fuzz
while read -r name; do
    $PYPY build_cffi_fuzz.py "$name"
    $CC $CFLAGS -fsanitize=fuzzer-no-link fuzzer_stub.c ./_pypy_fuzz_${name}.so \
        -L$PYPY_INSTALL_PATH/bin -lpypy3-c \
        -Wl,-rpath,'$ORIGIN' \
        $LIB_FUZZING_ENGINE -rdynamic -ldl -o fuzzer-${name}

    cp fuzzer-${name} _pypy_fuzz_${name}.so fuzz_${name}.py $OUT/
    cp $PYPY_INSTALL_PATH/bin/libpypy3.11-c.so $OUT/libpypy3-c.so
    if [ -d "corp-${name}" ]; then
        zip -j "$OUT/fuzzer-${name}_seed_corpus.zip" corp-${name}/*
    fi
    if [ -f "fuzzer-${name}.dict" ]; then
        cp "fuzzer-${name}.dict" "$OUT/"
    fi
done < fuzz_targets.txt

cp -R $PYPY_INSTALL_PATH $OUT/
