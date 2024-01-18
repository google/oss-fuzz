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
export LDFLAGS="$CXXFLAGS"
export LD="$CXX"
./configure --with-ossfuzz

# Ensure we build with few processors if memory gets exhausted
if [[ "$SANITIZER" = coverage ]]; then
    for mrkpath in fuzz_buffer_includes.target.mk fuzz_buffer_equals.target.mk fuzz_buffer_compare.target.mk fuzz_blob.target.mk fuzz_zlib_gzip_createUnzip.target.mk fuzz_zlib_createBrotliDecompress.target.mk fuzz_zlib_brotliDecompress.target.mk fuzz_zlib_brotliCompress.target.mk fuzz_string_decoder.target.mk fuzz_querystring_parse.target.mk fuzz_ParseSrvReply.target.mk fuzz_path_join.target.mk fuzz_env.target.mk fuzz_stream1.target.mk fuzz_strings.target.mk fuzz_diffieHellmanPEM.target.mk fuzz_createPrivateKeyPEM.target.mk fuzz_createPrivateKeyDER.target.mk fuzz_ParseSoaReply.target.mk fuzz_path_extname.target.mk fuzz_ParseCaaReply.target.mk fuzz_path_normalize.target.mk fuzz_path_relative.target.mk fuzz_createPrivateKeyJWK.target.mk fuzz_ParseMxReply.target.mk fuzz_path_format.target.mk fuzz_LoadBIO.target.mk fuzz_ClientHelloParser.target.mk fuzz_diffieHellmanJWK.target.mk fuzz_path_basename.target.mk fuzz_ParseNaptrReply.target.mk fuzz_path_isAbsolute.target.mk fuzz_tls_socket_request.target.mk fuzz_ParseGeneralReply.target.mk fuzz_diffieHellmanDER.target.mk fuzz_path_toNamespacedPath.target.mk fuzz_path_parse.target.mk fuzz_httpparser1.target.mk fuzz_path_dirname.target.mk fuzz_x509.target.mk fuzz_ParseTxtReply.target.mk fuzz_fs_write_read_append.target.mk fuzz_ParsePublicKey.target.mk fuzz_sign_verify.target.mk fuzz_path_resolve.target.mk fuzz_fs_write_open_read.target.mk libnode.target.mk; do
      sed -i 's/BUILDTYPE))/BUILDTYPE)) -fprofile-instr-generate -fcoverage-mapping/g' $SRC/node/out/${mrkpath}
    done
    make -j 3 || make -j1
else
	make -j$(nproc) || make -j1
fi

# Copy all fuzzers to OUT folder 
cp out/Release/fuzz_* ${OUT}/

# Create seed for fuzz_env
mkdir fuzz_env_seed
find ./test -name '*.js' -exec cp {} ./fuzz_env_seed/ \;
cd fuzz_env_seed
# Remove small files:
find -size -5k -delete
# Remove large files:
find -size +30k -delete
zip $OUT/fuzz_env_seed_corpus.zip ./*
# Add more seeds
cd $SRC/node/test/fuzzers/seed/fuzz_env
zip $OUT/fuzz_env_seed_corpus.zip ./*

cd $SRC/node/test/fuzzers/seed/fuzz_x509
zip $OUT/fuzz_x509_seed_corpus.zip ./*

