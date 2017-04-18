#!/bin/bash -eu
# Copyright 2017 Google Inc.
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

# Wireshark build.sh script inspired from projects/ffmpeg/build.sh

FUZZ_DISSECTORS="ip"

FUZZ_IP_PROTO_DISSECTORS="udp ospf"

FUZZ_TCP_PORT_DISSECTORS="bgp"
# FUZZ_TCP_PORT_DISSECTORS="$FUZZ_TCP_PORT_DISSECTORS bzr"   # disabled, cause of known problem.
# FUZZ_TCP_PORT_DISSECTORS="$FUZZ_TCP_PORT_DISSECTORS echo"  # disabled, too simple.

FUZZ_UDP_PORT_DISSECTORS="dns bootp"
# FUZZ_UDP_PORT_DISSECTORS="$FUZZ_UDP_PORT_DISSECTORS bfd"   # disabled, too simple.

FUZZ_MEDIA_TYPE_DISSECTORS="json"

# generate_fuzzer <fuzzer_target> <fuzzer_cflags>
generate_fuzzer()
{
  local fuzzer_target="$1" fuzzer_cflags="$2" fuzzer_name

  fuzzer_name="fuzzshark_$1"

  # -I$SRC/wireshark is correct, wireshark don't install header files.
  $CC $CFLAGS -I $SRC/wireshark/ `pkg-config --cflags glib-2.0` \
      $SRC/wireshark/tools/oss-fuzzshark.c \
      -c -o $WORK/${fuzzer_name}.o \
      $fuzzer_cflags

  $CXX $CXXFLAGS $WORK/${fuzzer_name}.o \
      -o $OUT/${fuzzer_name} \
      ${WIRESHARK_FUZZERS_COMMON_FLAGS}

  echo -en "[libfuzzer]\nmax_len = 1024\n" > $OUT/${fuzzer_name}.options
  if [ -d "$SAMPLES_DIR/${fuzzer_target}" ]; then
    zip -j $OUT/${fuzzer_name}_seed_corpus.zip $SAMPLES_DIR/${fuzzer_target}/*/*.bin
  fi
}

export WIRESHARK_INSTALL_PATH="$WORK/install"
mkdir -p "$WIRESHARK_INSTALL_PATH"

# Prepare Samples directory
SAMPLES_DIR="$WORK/samples"
mkdir -p "$SAMPLES_DIR"
cp -a $SRC/wireshark-fuzzdb/samples/* "$SAMPLES_DIR"

# compile static version of libs
# XXX, with static wireshark linking each fuzzer binary is ~240 MB (just libwireshark.a is 423 MBs).
# XXX, wireshark is not ready for including static plugins into binaries.
CONFOPTS="--disable-shared --enable-static --without-plugins"

# disable optional dependencies
CONFOPTS="$CONFOPTS --without-pcap --without-ssl --without-gnutls"

# need only libs, disable programs
CONFOPTS="$CONFOPTS --disable-wireshark --disable-tshark --disable-sharkd \
             --disable-dumpcap --disable-capinfos --disable-captype --disable-randpkt --disable-dftest \
             --disable-editcap --disable-mergecap --disable-reordercap --disable-text2pcap \
             --without-extcap \
         "

# Fortify and asan don't like each other ... :(
sed -i '/AC_WIRESHARK_GCC_FORTIFY_SOURCE_CHECK/d' configure.ac
./autogen.sh
./configure --prefix="$WIRESHARK_INSTALL_PATH" $CONFOPTS --disable-warnings-as-errors

make "-j$(nproc)"
make install

WIRESHARK_FUZZERS_COMMON_FLAGS="-lFuzzingEngine \
    -L"$WIRESHARK_INSTALL_PATH/lib" -lwireshark -lwiretap -lwsutil \
    -Wl,-Bstatic `pkg-config --libs glib-2.0` -pthread -lpcre -lgcrypt -lgpg-error -lz -Wl,-Bdynamic"

for dissector in $FUZZ_DISSECTORS; do
  generate_fuzzer "${dissector}" -DFUZZ_DISSECTOR_TARGET=\"$dissector\"
done

for dissector in $FUZZ_IP_PROTO_DISSECTORS; do
  generate_fuzzer "ip_proto-${dissector}" "-DFUZZ_DISSECTOR_TABLE=\"ip.proto\" -DFUZZ_DISSECTOR_TARGET=\"$dissector\""
done

for dissector in $FUZZ_TCP_PORT_DISSECTORS; do
  generate_fuzzer "tcp_port-${dissector}" "-DFUZZ_DISSECTOR_TABLE=\"tcp.port\" -DFUZZ_DISSECTOR_TARGET=\"$dissector\""
done

for dissector in $FUZZ_UDP_PORT_DISSECTORS; do
  generate_fuzzer "udp_port-${dissector}" "-DFUZZ_DISSECTOR_TABLE=\"udp.port\" -DFUZZ_DISSECTOR_TARGET=\"$dissector\""
done

for dissector in $FUZZ_MEDIA_TYPE_DISSECTORS; do
  generate_fuzzer "media_type-${dissector}" "-DFUZZ_DISSECTOR_TABLE=\"media_type\" -DFUZZ_DISSECTOR_TARGET=\"$dissector\""
done
