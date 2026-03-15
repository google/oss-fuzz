#!/bin/bash -eu

CFLAGS="$CFLAGS -fsanitize=address"
CXXFLAGS="$CXXFLAGS -fsanitize=address"

export CFLAGS
export CXXFLAGS

cd $SRC/mtr

# Build mtr using autotools
autoreconf -fi
./configure \
  --without-gtk \
  --disable-dependency-tracking \
  CC="$CC" \
  CXX="$CXX" \
  CFLAGS="$CFLAGS" \
  CXXFLAGS="$CXXFLAGS"

make -j$(nproc) || true

# Collect only .o files that have a corresponding .c source file
OBJ_FILES=""
for obj in $(find . -name '*.o' | sort); do
  src="${obj%.o}.c"
  if [ -f "$src" ]; then
    OBJ_FILES="$OBJ_FILES $obj"
  fi
done

# Filter out objects containing main() to avoid duplicate symbol errors
FILTERED_OBJ=""
for obj in $OBJ_FILES; do
  base=$(basename "$obj")
  case "$base" in
    mtr.o|mtr-mtr.o|packet.o) ;;
    *) FILTERED_OBJ="$FILTERED_OBJ $obj" ;;
  esac
done
OBJ_FILES="$FILTERED_OBJ"

echo "Object files for linking: $OBJ_FILES"

# Compile and link each fuzz target
for fuzz_target in fuzz_handle_received_ip4_packet fuzz_handle_received_ip6_packet fuzz_handle_error_queue_packet fuzz_parse_command; do
  $CC $CFLAGS -I. -I$SRC/mtr -I$SRC/mtr/ui -I$SRC/mtr/packet \
    -c $SRC/mtr/fuzz/${fuzz_target}.c -o $SRC/${fuzz_target}.o

  $CXX $CXXFLAGS \
    $SRC/${fuzz_target}.o \
    $OBJ_FILES \
    $LIB_FUZZING_ENGINE \
    -lncursesw -lcap -lresolv -lm \
    -o $OUT/${fuzz_target}
done

# Copy seed corpus
mkdir -p $OUT/corpus
for f in fuzz_handle_received_ip4_packet fuzz_handle_received_ip6_packet fuzz_handle_error_queue_packet fuzz_parse_command; do
  zip -j $OUT/${f}_seed_corpus.zip $SRC/mtr/fuzz/corpus/* 2>/dev/null || true
done
# Unzip all seeds into $OUT/corpus/ so the fuzzer can use them directly
for zip_file in $OUT/*_seed_corpus.zip; do
  [ -f "$zip_file" ] && unzip -o "$zip_file" -d $OUT/corpus/ 2>/dev/null || true
done
