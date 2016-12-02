#!/bin/sh

set -eu

./bootstrap --gnulib-srcdir="$SRC/gnulib" --no-git --skip-po
mkdir -p "$WORK/coreutils" && cd "$WORK/coreutils"

# Hack to avoid clang bug https://llvm.org/bugs/show_bug.cgi?id=16404
# which is triggered in xalloc_oversized() without the following
CFLAGS="$CFLAGS -D__STRICT_ANSI__=1"

# needed to allow configure run as root
export FORCE_UNSAFE_CONFIGURE=1

LIBS="-lfuzzer" "$SRC/coreutils/configure"

make -j"$(nproc)" clean all
make DESTDIR="$OUT" install-exec-am
