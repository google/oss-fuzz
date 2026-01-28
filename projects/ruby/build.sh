#!/bin/bash -eu
# Copyright 2025 Google LLC
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

# Build Ruby from source with static linking
# Strategy: Download latest stable Ruby, install it, then use as baseruby to build target Ruby

# Step 1: Download and install latest stable Ruby release as baseruby
# =====================================================================
echo "Step 1: Installing latest Ruby release as baseruby..."

RUBY_VERSION="3.3.6"  # Update this to latest stable version
RUBY_DOWNLOAD_URL="https://cache.ruby-lang.org/pub/ruby/3.3/ruby-${RUBY_VERSION}.tar.gz"
BASERUBY_PREFIX="$WORK/baseruby"

cd "$WORK"
if [ ! -f "ruby-${RUBY_VERSION}.tar.gz" ]; then
    echo "Downloading Ruby ${RUBY_VERSION}..."
    wget -q "$RUBY_DOWNLOAD_URL" -O "ruby-${RUBY_VERSION}.tar.gz"
    tar xzf "ruby-${RUBY_VERSION}.tar.gz"
fi

cd "ruby-${RUBY_VERSION}"

# Configure and build baseruby (without sanitizers for speed)
if [ ! -f "$BASERUBY_PREFIX/bin/ruby" ]; then
    echo "Building baseruby ${RUBY_VERSION}..."
    ./configure \
        --prefix="$BASERUBY_PREFIX" \
        --disable-install-doc \
        --disable-install-rdoc \
        --disable-jit-support \
        CFLAGS="-O2" \
        CXXFLAGS="-O2"
    
    make -j$(nproc)
    make install
    echo "Baseruby installed to $BASERUBY_PREFIX"
fi

export BASERUBY="$BASERUBY_PREFIX/bin/ruby"
export PATH="$BASERUBY_PREFIX/bin:$PATH"
$BASERUBY --version

# Step 2: Build target Ruby from source with static linking
# ===========================================================
echo ""
echo "Step 2: Building target Ruby with static linking..."

cd "$SRC/ruby"

# Clean any previous build
make distclean 2>/dev/null || true

# Generate configure script using Ruby's autogen.sh
if [ ! -f configure ]; then
    echo "Generating configure script..."
    ./autogen.sh
    
    # Copy config helpers from automake if they're missing
    if [ ! -f tool/config.sub ]; then
        echo "Copying config.sub and config.guess..."
        cp -f /usr/share/misc/config.sub tool/config.sub || \
        cp -f /usr/share/automake-*/config.sub tool/config.sub || true
        
        cp -f /usr/share/misc/config.guess tool/config.guess || \
        cp -f /usr/share/automake-*/config.guess tool/config.guess || true
        
        chmod +x tool/config.sub tool/config.guess
    fi
fi

# Configure target Ruby with static linking and sanitizers
echo "Configuring target Ruby with static linking..."

# Use the OSS-Fuzz provided CFLAGS and CXXFLAGS which already contain
# all necessary sanitizer flags from the build environment

./configure \
    --prefix="$WORK/ruby-install" \
    --disable-shared \
    --enable-static \
    --disable-install-doc \
    --disable-install-rdoc \
    --disable-install-capi \
    --with-static-linked-ext \
    --without-gmp \
    --disable-dtrace \
    --disable-jit-support \
    --with-baseruby="$BASERUBY"

# Build Ruby static library
echo "Building Ruby static library..."
make -j$(nproc) V=1

# Verify libruby-static.a exists
if [ ! -f libruby-static.a ]; then
    echo "ERROR: libruby-static.a not found after build"
    ls -la
    exit 1
fi

echo "libruby-static.a created successfully"

# Step 3: Set up paths for fuzzer builds
# ========================================
RUBY_BUILD_DIR="$SRC/ruby"
INC_RUBY="-I${RUBY_BUILD_DIR}/include -I${RUBY_BUILD_DIR}/.ext/include/x86_64-linux -I${RUBY_BUILD_DIR}"
LIBS_RUBY="${RUBY_BUILD_DIR}/libruby-static.a"

echo ""
echo "Ruby build complete!"
echo "Ruby include flags: $INC_RUBY"
echo "Ruby static library: $LIBS_RUBY"
echo ""


# Standard C++ fuzzers with common build pattern
STANDARD_FUZZERS="fuzz_regex
                  fuzz_string
                  fuzz_hash
                  fuzz_bignum
                  fuzz_array
                  fuzz_iseq
                  fuzz_pack
                  fuzz_ruby_parser
                  fuzz_prism"

for fuzzer in $STANDARD_FUZZERS; do
    echo "Building ${fuzzer}..."
    
    # Add Prism include path for fuzz_prism
    EXTRA_INCLUDES=""
    if [ "$fuzzer" = "fuzz_prism" ]; then
        EXTRA_INCLUDES="-I$RUBY_BUILD_DIR/prism"
    fi
    
    $CXX $CXXFLAGS $INC_RUBY $EXTRA_INCLUDES -c "$SRC/${fuzzer}.cpp" -o "$WORK/${fuzzer}.o"
    $CXX $CXXFLAGS $LIB_FUZZING_ENGINE "$WORK/${fuzzer}.o" \
        $LIBS_RUBY -lm -lpthread -ldl -lcrypt -lz -o "$OUT/${fuzzer}"
done

# Build json fuzzer seperately because it needs additional steps
echo "Building fuzz_json..."
JSON_DIR="$RUBY_BUILD_DIR/ext/json"

# Compile JSON vendor code (fpconv for float conversion)
$CC $CFLAGS $INC_RUBY -I"$JSON_DIR" \
    -c "$JSON_DIR/vendor/fpconv.c" -o "$WORK/json_fpconv.o"

# Compile the self-contained JSON fuzzer (includes parser.c directly) as C
$CC $CFLAGS $INC_RUBY -I"$JSON_DIR" -I"$JSON_DIR/vendor" -I"$JSON_DIR/simd" \
    -DHAVE_RB_ENC_INTERNED_STR -DHAVE_RB_HASH_BULK_INSERT -DHAVE_RB_HASH_NEW_CAPA \
    -DHAVE_RB_STR_TO_INTERNED_STR -DHAVE_STRNLEN \
    -c "$SRC/fuzz_json.c" -o "$WORK/fuzz_json.o"

# Link json assets together
$CXX $CXXFLAGS $LIB_FUZZING_ENGINE "$WORK/fuzz_json.o" "$WORK/json_fpconv.o" \
    $LIBS_RUBY -lm -lpthread -ldl -lcrypt -lz -o "$OUT/fuzz_json"

# create seeds
if [ -n "${OSS_FUZZ_CI-}" ]
then
	echo "skipping copora in CI"
else
	# skip seeds in CI
    find "$SRC/ruby" -type f -name '*.rb' | head -n 1000 | zip -@ "$OUT/fuzz_ruby_parser_seed_corpus.zip"
    find "$SRC/ruby" -type f -name '*.rb' | head -n 1000 | zip -@ "$OUT/fuzz_prism_seed_corpus.zip"
	find "$SRC/ruby" -type f -name '*.json' | head -n 100 | zip -@ "$OUT/fuzz_json_seed_corpus.zip"
fi

# Copy ruby.options to each fuzzer
ALL_FUZZERS="fuzz_regex fuzz_string fuzz_hash fuzz_bignum fuzz_array fuzz_iseq fuzz_pack fuzz_ruby_parser fuzz_prism fuzz_json"
for fuzzer in $ALL_FUZZERS; do
    cp "$SRC/ruby.options" "$OUT/${fuzzer}.options"
done
