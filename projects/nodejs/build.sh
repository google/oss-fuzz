#!/bin/bash -eu
# Copyright 2020 Google Inc.
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
rm $SRC/node/test/fuzzers/*
cp $SRC/fuzz_sources/* $SRC/node/test/fuzzers/

# Add the fuzzers to node.gyp
mkdir $SRC/modify-node-gyp
cd $SRC/modify-node-gyp
go mod init modify-node-gyp
mv $SRC/add_fuzzers_to_node_gyp.go ./main.go
go run main.go $SRC/node/node.gyp /tmp/updated-node.gyp
mv /tmp/updated-node.gyp $SRC/node/node.gyp

cd $SRC/node

# Coverage build takes very long and time outs in the CI which blocks changes. Ignore Coverage build in OSS-Fuzz CI for now:
if [[ -n "${OSS_FUZZ_CI-}" && "$SANITIZER" = coverage ]]; then
	exit 0
fi

if [[ "$SANITIZER" = coverage ]]; then
  export CFLAGS="${CFLAGS/"-fcoverage-mapping"/" "}"
  export CFLAGS="${CFLAGS/"-fprofile-instr-generate"/" "}"
  export CXXFLAGS="${CXXFLAGS/"-fcoverage-mapping"/" "}"
  export CXXFLAGS="${CXXFLAGS/"-fprofile-instr-generate"/" "}"
  echo "CFLAGS: ${CFLAGS}"
  echo "CXXFLAGS: ${CXXFLAGS}"
fi

# Build node
export CXXFLAGS="$CXXFLAGS -std=c++20 -stdlib=libc++"
export GN_ARGS='use_custom_libcxx=true'
export LDFLAGS="$CXXFLAGS"
export LDFLAGS="$LDFLAGS -stdlib=libc++"
export LD="$CXX"
./configure --with-ossfuzz

# Ensure we build with few processors if memory gets exhausted
if [[ "$SANITIZER" = coverage ]]; then
    for mrkpath in \
        fuzz_buffer_includes.target.mk \
        fuzz_buffer_equals.target.mk \
        fuzz_buffer_compare.target.mk \
        fuzz_blob.target.mk \
        fuzz_zlib_gzip_createUnzip.target.mk \
        fuzz_zlib_createBrotliDecompress.target.mk \
        fuzz_zlib_brotliDecompress.target.mk \
        fuzz_zlib_brotliCompress.target.mk \
        fuzz_string_decoder.target.mk \
        fuzz_querystring_parse.target.mk \
        fuzz_path_join.target.mk \
        fuzz_stream1.target.mk \
        fuzz_strings.target.mk \
        fuzz_diffieHellmanPEM.target.mk \
        fuzz_createPrivateKeyPEM.target.mk \
        fuzz_createPrivateKeyDER.target.mk \
        fuzz_path_extname.target.mk \
        fuzz_path_normalize.target.mk \
        fuzz_path_relative.target.mk \
        fuzz_createPrivateKeyJWK.target.mk \
        fuzz_path_format.target.mk \
        fuzz_ClientHelloParser.target.mk \
        fuzz_diffieHellmanJWK.target.mk \
        fuzz_path_basename.target.mk \
        fuzz_path_isAbsolute.target.mk \
        fuzz_tls_socket_request.target.mk \
        fuzz_diffieHellmanDER.target.mk \
        fuzz_path_toNamespacedPath.target.mk \
        fuzz_path_parse.target.mk \
        fuzz_httpparser1.target.mk \
        fuzz_path_dirname.target.mk \
        fuzz_x509.target.mk \
        fuzz_fs_write_read_append.target.mk \
        fuzz_sign_verify.target.mk \
        fuzz_path_resolve.target.mk \
        fuzz_fs_write_open_read.target.mk \
        libnode.target.mk
    do
        echo "sed'ing ${mrkpath}"
        sed -i 's/BUILDTYPE))/BUILDTYPE)) -fprofile-instr-generate -fcoverage-mapping/g' "$SRC/node/out/${mrkpath}"
    done
    make -j3 || make -j1
else
        make -j$(nproc) || make -j1
fi

# Move all fuzzers to OUT folder 
mv out/Release/fuzz_* ${OUT}/

