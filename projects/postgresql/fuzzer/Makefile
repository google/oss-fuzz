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
        $(top_builddir)/src/backend/libpostgres.a \

OBJS_FUZZERS = $(filter-out ../main/objfiles.txt, $(OBJS))

createdb: dbfuzz

fuzzer: simple_query_fuzzer \
	json_parser_fuzzer \
	protocol_fuzzer \
	fuzz_json \
	fuzz_json_incremental \
	fuzz_conninfo \
	fuzz_pglz \
	fuzz_unescapebytea \
	fuzz_b64decode \
	fuzz_saslprep \
	fuzz_parsepgarray \
	fuzz_pgbench_expr \
	fuzz_rawparser \
	fuzz_regex \
	fuzz_typeinput

simple_query_fuzzer json_parser_fuzzer: %: %.o fuzzer_initialize.o $(OBJS_FUZZERS)
	$(CXX) $(CFLAGS) $(call expand_subsys,$^) -o $@ -l:libicui18n.a -l:libicuuc.a -l:libicudata.a $(LIB_FUZZING_ENGINE) -lz -lpthread -ldl -lrt

simple_query_fuzzer.o json_parser_fuzzer.o protocol_fuzzer.o fuzzer_initialize.o: %.o: %.c
	$(CC) $(CFLAGS) $(CPPFLAGS) -c -o $@ $^

protocol_fuzzer: %: %.o $(OBJS_FUZZERS)
	$(CXX) $(CFLAGS) $(call expand_subsys,$^) -o $@ -l:libicui18n.a -l:libicuuc.a -l:libicudata.a $(LIB_FUZZING_ENGINE) -Wl,--wrap=exit -Wl,--wrap=pq_getbyte -lz -lpthread -ldl -lrt

#
# PostgreSQL's upstream fuzzing harnesses (src/test/fuzzing), vendored from
# commit 4a18907b412e77684bf888ad6d1b4844d220196a.  They are not part of the
# upstream master tree that this project clones, so the sources are kept in
# this directory and built here.  The main "make" run (in build.sh) has
# already produced all the libraries referenced below.
#

# Frontend libraries (already built by the top-level "make" run).
pg_fuzzer_srcdir = $(top_builddir)/..
libpq_fuzz_a = $(top_builddir)/src/interfaces/libpq/libpq.a
libpgcommon_fuzz_a = $(top_builddir)/src/common/libpgcommon.a
libpgport_fuzz_a = $(top_builddir)/src/port/libpgport.a
libpgfeutils_fuzz_a = $(top_builddir)/src/fe_utils/libpgfeutils.a
pgbench_objdir = $(top_builddir)/src/bin/pgbench

# libpgcommon.a is built with -DUSE_PRIVATE_ENCODING_FUNCS, so it exports the
# encoding-name helpers as pg_*_private, while libpq references them under
# their public names.  For frontend programs that link a static libpq we
# therefore also need a frontend build of encnames.c that exports the public
# names (see the comment in src/include/mb/pg_wchar.h).
fuzz_encnames_o = fuzz_encnames.o
fuzz_encnames.o: CPPFLAGS += -DFRONTEND

fuzz_fe_ldflags = $(LIB_FUZZING_ENGINE) -lz -lpthread -ldl -lrt

# Compile the frontend harnesses as frontend code and give them access to
# headers that live in the source tree (libpq-fe.h, pgbench.h) as well as to
# the Bison-generated exprparse.h in the build tree.
fuzz_json.o fuzz_json_incremental.o fuzz_conninfo.o fuzz_pglz.o \
fuzz_unescapebytea.o fuzz_b64decode.o fuzz_saslprep.o fuzz_parsepgarray.o \
fuzz_pgbench_expr.o: CPPFLAGS += -DFRONTEND

fuzz_conninfo.o fuzz_unescapebytea.o fuzz_parsepgarray.o: CPPFLAGS += -I$(pg_fuzzer_srcdir)/src/interfaces/libpq
fuzz_pgbench_expr.o: CPPFLAGS += -I$(pg_fuzzer_srcdir)/src/bin/pgbench -I$(top_builddir)/src/bin/pgbench -I$(pg_fuzzer_srcdir)/src/interfaces/libpq

fuzz_b64decode.o fuzz_conninfo.o fuzz_json.o fuzz_json_incremental.o \
fuzz_parsepgarray.o fuzz_pgbench_expr.o fuzz_pglz.o fuzz_rawparser.o \
fuzz_regex.o fuzz_saslprep.o fuzz_typeinput.o fuzz_unescapebytea.o: %.o: %.c
	$(CC) $(CFLAGS) $(CPPFLAGS) -c -o $@ $<

fuzz_encnames.o: $(pg_fuzzer_srcdir)/src/common/encnames.c
	$(CC) $(CFLAGS) $(CPPFLAGS) -c -o $@ $<

# Frontend harnesses that only need libpgcommon.
fuzz_json fuzz_json_incremental fuzz_b64decode fuzz_pglz fuzz_saslprep: %: %.o
	$(CXX) $(CFLAGS) $^ $(libpgcommon_fuzz_a) $(libpgport_fuzz_a) -o $@ $(fuzz_fe_ldflags)

# Frontend harnesses that need libpq (public encoding-name functions).
fuzz_conninfo fuzz_unescapebytea: %: %.o $(fuzz_encnames_o)
	$(CXX) $(CFLAGS) $^ $(libpq_fuzz_a) $(libpgcommon_fuzz_a) $(libpgport_fuzz_a) -o $@ $(fuzz_fe_ldflags)

# Frontend harness for parsePGArray(), which lives in fe_utils.  string_utils
# pulls in libpq (PQExpBuffer helpers), so link those too.
fuzz_parsepgarray: %: %.o $(fuzz_encnames_o)
	$(CXX) $(CFLAGS) $^ $(libpgfeutils_fuzz_a) $(libpq_fuzz_a) $(libpgcommon_fuzz_a) $(libpgport_fuzz_a) -o $@ $(fuzz_fe_ldflags)

# Frontend harness for the pgbench expression parser.  Reuses the Bison/Flex
# outputs that the pgbench build produced and links them against the same
# libraries pgbench uses (fe_utils for psqlscan, libpq, libpgcommon).
fuzz_pgbench_expr: %: %.o $(pgbench_objdir)/exprparse.o $(pgbench_objdir)/exprscan.o $(fuzz_encnames_o)
	$(CXX) $(CFLAGS) $^ $(libpgfeutils_fuzz_a) $(libpq_fuzz_a) $(libpgcommon_fuzz_a) $(libpgport_fuzz_a) -o $@ $(fuzz_fe_ldflags)

# Backend harnesses link against the whole backend, like the project fuzzers
# above.  They define their own progname/parse_dispatch_option stubs so the
# linker does not pull in main.o from libpostgres.a.
fuzz_rawparser fuzz_regex fuzz_typeinput: %: %.o $(OBJS_FUZZERS)
	$(CXX) $(CFLAGS) $(call expand_subsys,$^) -o $@ -l:libicui18n.a -l:libicuuc.a -l:libicudata.a $(LIB_FUZZING_ENGINE) -lz -lpthread -ldl -lrt

# submake-libpgport and temp-install both build src/port and src/common.  As
# order-only prerequisites of dbfuzz they are otherwise free to run
# concurrently under "make -j", and the two "ar crs libpgcommon_shlib.a"
# invocations then race ("ar: unable to copy file ...: No such file or
# directory").  Force submake-libpgport to complete first.
temp-install: | submake-libpgport

dbfuzz: dbfuzz.o | submake-libpgport temp-install
	$(CC) $(CFLAGS) $^ $(LDFLAGS) $(LDFLAGS_EX) $(LIBS) -o $@ \
	&& PATH="$(abs_top_builddir)/tmp_install$(bindir):$$PATH" LD_LIBRARY_PATH="$(abs_top_builddir)/tmp_install/usr/local/pgsql/lib" ./dbfuzz

dbfuzz.o: dbfuzz.c $(top_builddir)/src/port/pg_config_paths.h
dbfuzz.o: override CPPFLAGS := $(CPPFLAGS) -I$(top_builddir)/src/port -I$(top_builddir)/../src/test/regress '-DSHELLPROG="$(SHELL)"'

$(top_builddir)/src/port/pg_config_paths.h: | submake-libpgport
	$(MAKE) -C $(top_builddir)/src/port pg_config_paths.h
