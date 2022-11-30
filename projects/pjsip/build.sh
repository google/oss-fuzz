#!/bin/bash -eu
# Copyright 2022 Google LLC
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
export CXXFLAGS="$CFLAGS"
export LDFLAGS="$CFLAGS"

./configure \
--disable-ffmpeg --disable-ssl \
--disable-speex-aec --disable-speex-codec \
--disable-g7221-codec --disable-gsm-codec --disable-ilbc-codec \
--disable-resample --disable-libsrtp --disable-libwebrtc --disable-libyuv

make dep
make -j$(nproc) --ignore-errors
make fuzz


pushd tests/fuzz/
cp fuzz-json $OUT/fuzz-json
cp fuzz-xml $OUT/fuzz-xml
cp fuzz-sdp $OUT/fuzz-sdp
cp fuzz-stun $OUT/fuzz-stun
cp fuzz-sip $OUT/fuzz-sip
popd

pushd tests/fuzz/seed/
cp fuzz-json_seed_corpus.zip $OUT/fuzz-json_seed_corpus.zip
cp fuzz-xml_seed_corpus.zip $OUT/fuzz-xml_seed_corpus.zip
cp fuzz-sdp_seed_corpus.zip $OUT/fuzz-sdp_seed_corpus.zip
cp fuzz-stun_seed_corpus.zip $OUT/fuzz-stun_seed_corpus.zip
cp fuzz-sip_seed_corpus.zip $OUT/fuzz-sip_seed_corpus.zip
popd
