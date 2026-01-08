#!/bin/bash -eu
# OSS-Fuzz build script for libiqxmlrpc
# Copyright (C) 2024 libiqxmlrpc contributors

# Build libxml2 as static library
cd $SRC
if [ ! -d libxml2 ]; then
    git clone --depth 1 https://gitlab.gnome.org/GNOME/libxml2.git
fi
cd libxml2
mkdir -p build && cd build
cmake .. \
    -DCMAKE_C_COMPILER=$CC \
    -DCMAKE_C_FLAGS="$CFLAGS" \
    -DBUILD_SHARED_LIBS=OFF \
    -DLIBXML2_WITH_PYTHON=OFF \
    -DLIBXML2_WITH_LZMA=OFF \
    -DLIBXML2_WITH_ZLIB=OFF \
    -DLIBXML2_WITH_ICU=OFF
make -j$(nproc)
LIBXML2_DIR="$SRC/libxml2"
LIBXML2_LIB="$LIBXML2_DIR/build/libxml2.a"
LIBXML2_INCLUDE_SRC="$LIBXML2_DIR/include"
LIBXML2_INCLUDE_BUILD="$LIBXML2_DIR/build"

# Build libiqxmlrpc with fuzzing instrumentation as static library
cd $SRC/libiqxmlrpc
mkdir -p build
cd build
cmake .. \
    -DCMAKE_C_COMPILER=$CC \
    -DCMAKE_CXX_COMPILER=$CXX \
    -DCMAKE_C_FLAGS="$CFLAGS" \
    -DCMAKE_CXX_FLAGS="$CXXFLAGS -std=c++11 -DBOOST_TIMER_ENABLE_DEPRECATED -I$LIBXML2_INCLUDE_SRC -I$LIBXML2_INCLUDE_BUILD" \
    -DBUILD_SHARED_LIBS=OFF \
    -Dbuild_tests=OFF \
    -DLIBXML2_INCLUDE_DIR="$LIBXML2_INCLUDE_SRC;$LIBXML2_INCLUDE_BUILD" \
    -DLIBXML2_LIBRARY="$LIBXML2_LIB"

make -j$(nproc)
cd ..

# Build fuzz targets with static linking
for fuzzer in fuzz/fuzz_*.cc; do
    name=$(basename "$fuzzer" .cc)
    $CXX $CXXFLAGS -std=c++11 -DBOOST_TIMER_ENABLE_DEPRECATED \
        -I. -I"$LIBXML2_INCLUDE_SRC" -I"$LIBXML2_INCLUDE_BUILD" \
        "$fuzzer" \
        -o "$OUT/$name" \
        build/libiqxmlrpc/libiqxmlrpc.a \
        "$LIBXML2_LIB" \
        $LIB_FUZZING_ENGINE \
        -Wl,-Bstatic -lboost_date_time -lboost_thread -lboost_system \
        -Wl,-Bdynamic -lpthread
done

# Copy seed corpus
mkdir -p "$OUT/fuzz_request_seed_corpus"
mkdir -p "$OUT/fuzz_response_seed_corpus"

# Create seed corpus for request fuzzer
cat > "$OUT/fuzz_request_seed_corpus/sample1.xml" << 'EOF'
<?xml version="1.0"?>
<methodCall>
  <methodName>examples.getStateName</methodName>
  <params>
    <param><value><i4>41</i4></value></param>
  </params>
</methodCall>
EOF

cat > "$OUT/fuzz_request_seed_corpus/sample2.xml" << 'EOF'
<?xml version="1.0"?>
<methodCall>
  <methodName>sample.sumAndDifference</methodName>
  <params>
    <param><value><int>5</int></value></param>
    <param><value><int>3</int></value></param>
  </params>
</methodCall>
EOF

# Create seed corpus for response fuzzer
cat > "$OUT/fuzz_response_seed_corpus/sample1.xml" << 'EOF'
<?xml version="1.0"?>
<methodResponse>
  <params>
    <param><value><string>South Dakota</string></value></param>
  </params>
</methodResponse>
EOF

cat > "$OUT/fuzz_response_seed_corpus/sample2.xml" << 'EOF'
<?xml version="1.0"?>
<methodResponse>
  <fault>
    <value>
      <struct>
        <member>
          <name>faultCode</name>
          <value><int>4</int></value>
        </member>
        <member>
          <name>faultString</name>
          <value><string>Too many parameters.</string></value>
        </member>
      </struct>
    </value>
  </fault>
</methodResponse>
EOF

# Zip seed corpora
cd "$OUT"
zip -q fuzz_request_seed_corpus.zip fuzz_request_seed_corpus/*
zip -q fuzz_response_seed_corpus.zip fuzz_response_seed_corpus/*
rm -rf fuzz_request_seed_corpus fuzz_response_seed_corpus
