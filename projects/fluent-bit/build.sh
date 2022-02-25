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
cd fluent-bit
sed -i 's/malloc(/fuzz_malloc(/g' ./lib/msgpack-c/src/zone.c
sed -i 's/struct msgpack_zone_chunk {/void *fuzz_malloc(size_t size) {if (size > 0xa00000) return NULL;\nreturn malloc(size);}\nstruct msgpack_zone_chunk {/g' ./lib/msgpack-c/src/zone.c

cd build

export CFLAGS="$CFLAGS -fcommon -DFLB_TESTS_OSSFUZZ=ON"
export CXXFLAGS="$CXXFLAGS -fcommon -DFLB_TESTS_OSSFUZZ=ON"

# Commandline arguments to turn off a lot of plugins.
INPUT_PLUGINS="-DFLB_IN_COLLECTD=OFF -DFLB_IN_CPU=OFF -DFLB_IN_DISK=OFF -DFLB_IN_DOCKER=OFF -DFLB_IN_EXEC=OFF -DFLB_IN_FORWARD=OFF -DFLB_IN_HEAD=OFF -DFLB_IN_HEALTH=OFF -DFLB_IN_KMSG=OFF -DFLB_IN_MEM=OFF -DFLB_IN_MQTT=OFF -DFLB_IN_NETIF=OFF -DFLB_IN_PROC=OFF -DFLB_IN_RANDOM=OFF -DFLB_IN_SERIAL=OFF -DFLB_IN_STDIN=OFF -DFLB_IN_SYSLOG=OFF -DFLB_IN_SYSTEMD=OFF -DFLB_IN_TAIL=OFF -DFLB_IN_TCP=OFF -DFLB_IN_THERMAL=OFF -DFLB_IN_WINLOG=OFF"
OUTPUT_PLUGINS="-DFLB_STREAM_PROCESSOR=Off -DFLB_LUAJIT=OFF -DFLB_FILTER_GREP=OFF -DFLB_FILTER_REWRITE_TAG=OFF -DFLB_OUT_AZURE=OFF -DFLB_OUT_BIGQUERY=OFF -DFLB_OUT_COUNTER=OFF -DFLB_OUT_DATADOG=OFF -DFLB_OUT_ES=OFF -DFLB_OUT_FILE=OFF -DFLB_OUT_FLOWCOUNTER=OFF -DFLB_OUT_FORWARD=OFF -DFLB_OUT_GELF=OFF -DFLB_OUT_HTTP=OFF -DFLB_OUT_INFLUXDB=OFF -DFLB_OUT_KAFKA=OFF -DFLB_OUT_KAFKA_REST=OFF -DFLB_OUT_NATS=OFF -DFLB_OUT_NULL=OFF -DFLB_OUT_PGSQL=OFF -DFLB_OUT_PLOT=OFF -DFLB_OUT_SLACK=OFF -DFLB_OUT_SPLUNK=OFF -DFLB_OUT_STACKDRIVER=OFF -DFLB_OUT_STDOUT=OFF -DFLB_OUT_TCP=OFF -DFLB_OUT_SYSLOG=OFF -DFLB_OUT_NRLOGS=OFF  -DFLB_OUT_LOKI=OFF"
FILTER_PLUGINS="-DFLB_FILTER_PARSER=ON  -DFLB_FILTER_RECORD_MODIFIER=OFF -DFLB_FILTER_MODIFY=OFF -DFLB_FILTER_THROTTLE=OFF -DFLB_FILTER_KUBERNETES=OFF -DFLB_FILTER_NEST=OFF -DFLB_FILTER_PARSER=OFF -DFLB_FILTER_AWS=OFF -DFLB_FILTER_ALTER_SIZE=OFF"
EXTRA_FLAGS="-DFLB_BINARY=OFF -DFLB_EXAMPLES=OFF DFLB_METRICS=ON -DFLB_DEBUG=On -DMBEDTLS_FATAL_WARNINGS=OFF"
cmake -DFLB_TESTS_INTERNAL=ON \
      -DFLB_TESTS_INTERNAL_FUZZ=ON \
      -DFLB_TESTS_OSSFUZZ=ON \
      ${EXTRA_FLAGS} \
      ${INPUT_PLUGINS} \
      ${FILTER_PLUGINS} \
      ${OUTPUT_PLUGINS} ..
make

cp $SRC/fluent-bit/build/bin/*OSSFUZZ ${OUT}/
