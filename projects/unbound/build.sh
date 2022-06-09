#!/bin/bash -eux
# Copyright 2019 Google Inc.
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
# util/storage/lookup3.c has some code that triggers the address sanitizer, but
# according to a comment is OK. -DVALGRIND turns on an alternate version of that
# code.
CFLAGS="${CFLAGS} -DVALGRIND=1"
./configure
make -j6 all

$CC $CFLAGS -I. -DSRCDIR=. -c -o parse_packet_fuzzer.o parse_packet_fuzzer.c
$CC $CFLAGS -I. -DSRCDIR=. -c -o fuzz_1.o fuzz_1.c
$CC $CFLAGS -I. -DSRCDIR=. -c -o fuzz_2.o fuzz_2.c
$CC $CFLAGS -I. -DSRCDIR=. -c -o fuzz_3.o fuzz_3.c
$CC $CFLAGS -I. -DSRCDIR=. -c -o fuzz_4.o fuzz_4.c

# get the LIBOBJS with the replaced functions needed for linking.
LIBOBJS=`make --eval 'echolibobjs: ; @echo "$(LIBOBJS)"' echolibobjs`

OBJECTS_TO_LINK="dns.o infra.o rrset.o dname.o \
  msgencode.o as112.o msgparse.o msgreply.o packed_rrset.o iterator.o \
  iter_delegpt.o iter_donotq.o iter_fwd.o iter_hints.o iter_priv.o \
  iter_resptype.o iter_scrub.o iter_utils.o localzone.o mesh.o modstack.o view.o \
  outbound_list.o alloc.o config_file.o configlexer.o configparser.o \
  fptr_wlist.o edns.o locks.o log.o mini_event.o module.o net_help.o random.o \
  rbtree.o regional.o rtt.o dnstree.o lookup3.o lruhash.o slabhash.o \
  tcp_conn_limit.o timehist.o tube.o winsock_event.o autotrust.o val_anchor.o \
  validator.o val_kcache.o val_kentry.o val_neg.o val_nsec3.o val_nsec.o \
  val_secalgo.o val_sigcrypt.o val_utils.o dns64.o authzone.o \
  respip.o netevent.o listen_dnsport.o outside_network.o ub_event.o keyraw.o \
  sbuffer.o wire2str.o parse.o parseutil.o rrdef.o str2wire.o libunbound.o \
  libworker.o context.o rpz.o"

$CXX $CXXFLAGS -std=c++11 \
  $LIB_FUZZING_ENGINE \
  -lssl -lcrypto -pthread \
  -o $OUT/parse_packet_fuzzer \
  parse_packet_fuzzer.o \
  $OBJECTS_TO_LINK \
  $LIBOBJS

$CXX $CXXFLAGS -std=c++11 \
  $LIB_FUZZING_ENGINE \
  -lssl -lcrypto -pthread \
  -o $OUT/fuzz_1_fuzzer \
  fuzz_1.o \
  $OBJECTS_TO_LINK \
  $LIBOBJS

$CXX $CXXFLAGS -std=c++11 \
  $LIB_FUZZING_ENGINE \
  -lssl -lcrypto -pthread \
  -o $OUT/fuzz_2_fuzzer \
  fuzz_2.o \
  $OBJECTS_TO_LINK \
  $LIBOBJS

$CXX $CXXFLAGS -std=c++11 \
  $LIB_FUZZING_ENGINE \
  -lssl -lcrypto -pthread \
  -o $OUT/fuzz_3_fuzzer \
  fuzz_3.o \
  $OBJECTS_TO_LINK \
  $LIBOBJS

$CXX $CXXFLAGS -std=c++11 \
  $LIB_FUZZING_ENGINE \
  -lssl -lcrypto -pthread \
  -o $OUT/fuzz_4_fuzzer \
  fuzz_4.o \
  $OBJECTS_TO_LINK \
  $LIBOBJS

wget --directory-prefix $OUT https://github.com/jsha/unbound/raw/fuzzing-corpora/testdata/parse_packet_fuzzer_seed_corpus.zip
