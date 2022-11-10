#-------------------------------------------------------------------------
#
# Makefile for the fuzzer module
#
# src/backend/fuzzer/Makefile
#
#-------------------------------------------------------------------------
subdir = src/backend/fuzzer
top_builddir = ../../..
include $(top_builddir)/src/Makefile.global

subsysfilename = objfiles.txt

SUBDIROBJS = $(SUBDIRS:%=%/$(subsysfilename))

# make function to expand objfiles.txt contents
expand_subsys = $(foreach file,$(1),$(if $(filter %/objfiles.txt,$(file)),$(patsubst ../../src/backend/%,%,$(addprefix $(top_builddir)/,$(shell cat $(file)))),$(file)))

objfiles.txt: Makefile $(SUBDIROBJS) $(OBJS_FUZZERS)
# Don't rebuild the list if only the OBJS have changed.
	 $(if $(filter-out $(OBJS_FUZZERS),$?),( $(if $(SUBDIROBJS),cat $(SUBDIROBJS); )echo $(addprefix $(subdir)/,$(OBJS_FUZZERS)) ) >$@,touch $@)

SUBDIRS = ../access ../bootstrap ../catalog ../parser ../commands ../executor ../foreign ../lib ../libpq \
	../main ../nodes ../optimizer ../partitioning ../port ../postmaster \
	../regex ../replication ../rewrite ../backup \
	../statistics ../storage ../tcop ../tsearch ../utils $(top_builddir)/src/timezone \
	../jit

OBJS = \
	$(LOCALOBJS) \
	$(SUBDIROBJS) \
	$(top_builddir)/src/common/libpgcommon_srv.a \
	$(top_builddir)/src/port/libpgport_srv.a \

OBJS_FUZZERS = $(filter-out ../main/objfiles.txt, $(OBJS))

createdb: dbfuzz

fuzzer: simple_query_fuzzer \
	json_parser_fuzzer \
	protocol_fuzzer

simple_query_fuzzer json_parser_fuzzer: %: %.o fuzzer_initialize.o $(OBJS_FUZZERS)
	$(CXX) $(CFLAGS) $(call expand_subsys,$^) -o $@ $(LIB_FUZZING_ENGINE) -lz

simple_query_fuzzer.o json_parser_fuzzer.o protocol_fuzzer.o fuzzer_initialize.o: %.o: %.c
	$(CC) $(CFLAGS) $(CPPFLAGS) -c -o $@ $^ 

protocol_fuzzer: %: %.o $(OBJS_FUZZERS)
	$(CXX) $(CFLAGS) $(call expand_subsys,$^) -o $@ $(LIB_FUZZING_ENGINE) -Wl,--wrap=exit -Wl,--wrap=pq_getbyte  -lz

dbfuzz: dbfuzz.o | submake-libpgport temp-install
	$(CC) $(CFLAGS) $^ $(LDFLAGS) $(LDFLAGS_EX) $(LIBS) -o $@ \
	&& PATH="$(abs_top_builddir)/tmp_install$(bindir):$$PATH" LD_LIBRARY_PATH="$(abs_top_builddir)/tmp_install/usr/local/pgsql/lib" ./dbfuzz

dbfuzz.o: dbfuzz.c $(top_builddir)/src/port/pg_config_paths.h 
dbfuzz.o: override CPPFLAGS := $(CPPFLAGS) -I$(top_builddir)/src/port -I$(top_builddir)/../src/test/regress '-DSHELLPROG="$(SHELL)"'

$(top_builddir)/src/port/pg_config_paths.h: | submake-libpgport
	$(MAKE) -C $(top_builddir)/src/port pg_config_paths.h
