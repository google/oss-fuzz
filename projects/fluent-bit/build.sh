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
cd fluent-bit/build

# Commandline arguments to turn off a lot of plugins.
INPUT_PLUGINS="-DFLB_IN_COLLECTD=OFF -DFLB_IN_CPU=OFF -DFLB_IN_DISK=OFF -DFLB_IN_DOCKER=OFF -DFLB_IN_EXEC=OFF -DFLB_IN_FORWARD=OFF -DFLB_IN_HEAD=OFF -DFLB_IN_HEALTH=OFF -DFLB_IN_KMSG=OFF -DFLB_IN_MEM=OFF -DFLB_IN_MQTT=OFF -DFLB_IN_NETIF=OFF -DFLB_IN_PROC=OFF -DFLB_IN_RANDOM=OFF -DFLB_IN_SERIAL=OFF -DFLB_IN_STDIN=OFF -DFLB_IN_SYSLOG=OFF -DFLB_IN_SYSTEMD=OFF -DFLB_IN_TAIL=OFF -DFLB_IN_TCP=OFF -DFLB_IN_THERMAL=OFF -DFLB_IN_WINLOG=OFF"
OUTPUT_PLUGINS="-DFLB_RECORD_ACCESSOR=Off -DFLB_STREAM_PROCESSOR=Off -DFLB_LUAJIT=OFF -DFLB_FILTER_GREP=OFF -DFLB_FILTER_REWRITE_TAG=OFF -DFLB_OUT_AZURE=OFF -DFLB_OUT_BIGQUERY=OFF -DFLB_OUT_COUNTER=OFF -DFLB_OUT_DATADOG=OFF -DFLB_OUT_ES=OFF -DFLB_OUT_FILE=OFF -DFLB_OUT_FLOWCOUNTER=OFF -DFLB_OUT_FORWARD=OFF -DFLB_OUT_GELF=OFF -DFLB_OUT_HTTP=OFF -DFLB_OUT_INFLUXDB=OFF -DFLB_OUT_KAFKA=OFF -DFLB_OUT_KAFKA_REST=OFF -DFLB_OUT_NATS=OFF -DFLB_OUT_NULL=OFF -DFLB_OUT_PGSQL=OFF -DFLB_OUT_PLOT=OFF -DFLB_OUT_SLACK=OFF -DFLB_OUT_SPLUNK=OFF -DFLB_OUT_STACKDRIVER=OFF -DFLB_OUT_STDOUT=OFF -DFLB_OUT_TCP=OFF -DFLB_OUT_SYSLOG=OFF"
FILTER_PLUGINS="-DFLB_FILTER_RECORD_MODIFIER=OFF -DFLB_FILTER_MODIFY=OFF -DFLB_FILTER_THROTTLE=OFF -DFLB_FILTER_KUBERNETES=OFF -DFLB_FILTER_NEST=OFF -DFLB_FILTER_PARSER=OFF -DFLB_FILTER_AWS=OFF -DFLB_FILTER_ALTER_SIZE=OFF"

cmake ${INPUT_PLUGINS} ${FILTER_PLUGINS} ${OUTPUT_PLUGINS} -DCMAKE_VERBOSE_MAKEFILE:BOOL=ON ..
make

# Copy over the fuzzers
cp ../tests/internal/fuzzers/* .

# Now compile the fuzzers
$CC $CFLAGS -c flb_json_fuzzer.c -o flb_json_fuzzer.o
$CXX flb_json_fuzzer.o -o $OUT/flb_json_fuzzer $CXXFLAGS $LIB_FUZZING_ENGINE  library/libfluent-bit.a  library/libmk_core.a library/libjsmn.a library/libmsgpackc.a library/libmpack-static.a

for fuzzer_name in parse_json parse_ltsv parse_logfmt
do
    $CC $CFLAGS -c ${fuzzer_name}_fuzzer.c -o ${fuzzer_name}_fuzzer.o -I/src/fluent-bit/include -I/src/fluent-bit/lib -I/src/fluent-bit/lib/flb_libco -I/src/fluent-bit/lib/rbtree -I/src/fluent-bit/lib/msgpack-3.2.0/include -I/src/fluent-bit/lib/chunkio/include -I/src/fluent-bit/lib/LuaJIT-2.1.0-beta3/src -I/src/fluent-bit/lib/monkey/include -I/src/fluent-bit/lib/mbedtls-2.16.5/include -I/src/fluent-bit/lib/sqlite-amalgamation-3310000 -I/src/fluent-bit/lib/mpack-amalgamation-1.0/src -I/src/fluent-bit/lib/miniz -I/src/fluent-bit/lib/onigmo -I/src/fluent-bit/build/include -I/src/fluent-bit/lib/tutf8e/include -I/src/fluent-bit/build/backtrace-prefix/include -I/src/fluent-bit/build/lib/msgpack-3.2.0/include

    $CXX ${fuzzer_name}_fuzzer.o -o $OUT/${fuzzer_name}_fuzzer $CXXFLAGS $LIB_FUZZING_ENGINE library/libfluent-bit.a library/libflb-plugin-in_emitter.a library/libflb-plugin-in_dummy.a library/libflb-plugin-in_statsd.a library/libflb-plugin-in_storage_backlog.a library/libflb-plugin-in_lib.a library/libflb-plugin-out_exit.a library/libflb-plugin-out_logdna.a library/libflb-plugin-out_newrelic.a library/libflb-plugin-out_td.a library/libflb-plugin-out_lib.a library/libflb-plugin-filter_stdout.a library/libfluent-bit.a -lm -lrt library/libmk_core.a library/libjsmn.a library/libmsgpackc.a library/libmpack-static.a library/libchunkio-static.a library/libcio-crc32.a library/libminiz.a library/libflb-plugin-proxy-go.a library/libmbedtls.a library/libmbedx509.a library/libmbedcrypto.a library/libco.a library/librbtree.a lib/libonigmo.a library/libsqlite3.a -ldl library/libtutf8e.a
done
