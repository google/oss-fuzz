#!/bin/bash -eux
cp fuzztest_seed_corpus.zip $OUT/
# util/storage/lookup3.c has some code that triggers the address sanitizer, but
# according to a comment is OK. -DVALGRIND turns on an alternate version of that
# code.
CFLAGS="${CFLAGS} -DVALGRIND=1"
./configure
make all

$CC $CFLAGS -I. -DSRCDIR=. -c -o fuzztest.o fuzztest.c

$CXX $CXXFLAGS -std=c++11 \
  -lFuzzingEngine \
  -lssl -lcrypto \
  -o $OUT/fuzztest \
  -pthread fuzztest.o dns.o infra.o rrset.o dname.o \
  msgencode.o as112.o msgparse.o msgreply.o packed_rrset.o iterator.o \
  iter_delegpt.o iter_donotq.o iter_fwd.o iter_hints.o iter_priv.o \
  iter_resptype.o iter_scrub.o iter_utils.o localzone.o mesh.o modstack.o view.o \
  outbound_list.o alloc.o config_file.o configlexer.o configparser.o \
  fptr_wlist.o edns.o locks.o log.o mini_event.o module.o net_help.o random.o \
  rbtree.o regional.o rtt.o dnstree.o lookup3.o lruhash.o slabhash.o \
  tcp_conn_limit.o timehist.o tube.o winsock_event.o autotrust.o val_anchor.o \
  validator.o val_kcache.o val_kentry.o val_neg.o val_nsec3.o val_nsec.o \
  val_secalgo.o val_sigcrypt.o val_utils.o dns64.o cachedb.o redis.o authzone.o \
  respip.o netevent.o listen_dnsport.o outside_network.o ub_event.o keyraw.o \
  sbuffer.o wire2str.o parse.o parseutil.o rrdef.o str2wire.o strlcat.o \
  getentropy_linux.o reallocarray.o libunbound.o \
  explicit_bzero.o libworker.o context.o \
  strlcpy.o arc4random.o arc4random_uniform.o arc4_lock.o
