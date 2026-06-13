#!/bin/bash -eu

cd $SRC/miniupnp/miniupnpc

# Build miniupnpc as a static library
$CC $CFLAGS -DMINIUPNPC_SET_SOCKET_TIMEOUT \
    -DMINIUPNPC_GET_SRC_ADDR \
    -D_BSD_SOURCE -D_DEFAULT_SOURCE \
    -D_XOPEN_SOURCE=600 \
    -c src/minixml.c -o minixml.o
$CC $CFLAGS -c src/upnpreplyparse.c -o upnpreplyparse.o
$CC $CFLAGS -c src/igd_desc_parse.c -o igd_desc_parse.o
$CC $CFLAGS -c src/portlistingparse.c -o portlistingparse.o
$CC $CFLAGS -c src/minisoap.c -o minisoap.o

ar rcs libminiupnpc.a minixml.o upnpreplyparse.o igd_desc_parse.o \
       portlistingparse.o minisoap.o

# Fuzzer: minixml parser — parses UPnP XML responses from network
$CC $CFLAGS -Iinclude -c $SRC/fuzz_minixml.c -o fuzz_minixml.o
$CXX $CXXFLAGS $LIB_FUZZING_ENGINE fuzz_minixml.o libminiupnpc.a \
    -o $OUT/fuzz_minixml

# Fuzzer: UPnP reply parser — parses UPnP SOAP/SSDP response key-value pairs
$CC $CFLAGS -Iinclude -c $SRC/fuzz_upnpreplyparse.c -o fuzz_upnpreplyparse.o
$CXX $CXXFLAGS $LIB_FUZZING_ENGINE fuzz_upnpreplyparse.o libminiupnpc.a \
    -o $OUT/fuzz_upnpreplyparse

# Fuzzer: IGD description parser — parses UPnP IGD XML device descriptions
$CC $CFLAGS -Iinclude -c $SRC/fuzz_igd_desc_parse.c -o fuzz_igd_desc_parse.o
$CXX $CXXFLAGS $LIB_FUZZING_ENGINE fuzz_igd_desc_parse.o libminiupnpc.a \
    -o $OUT/fuzz_igd_desc_parse

# Fuzzer: port listing parser — parses GetListOfPortMappings XML responses
$CC $CFLAGS -Iinclude -c $SRC/fuzz_portlistingparse.c -o fuzz_portlistingparse.o
$CXX $CXXFLAGS $LIB_FUZZING_ENGINE fuzz_portlistingparse.o libminiupnpc.a \
    -o $OUT/fuzz_portlistingparse

# Seed corpus from existing test inputs
zip -j $OUT/fuzz_minixml_seed_corpus.zip \
    src/testdesc/*.xml 2>/dev/null || true
zip -j $OUT/fuzz_igd_desc_parse_seed_corpus.zip \
    src/testdesc/*.xml 2>/dev/null || true
zip -j $OUT/fuzz_upnpreplyparse_seed_corpus.zip \
    testreplyparse/*.namevalue 2>/dev/null || true
