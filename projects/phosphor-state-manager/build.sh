#!/bin/bash -eu
$CXX $CXXFLAGS -std=c++23 -I$SRC/phosphor-state-manager -I$SRC/mock_includes \
    $SRC/target_parser_fuzzer.cpp \
    $SRC/phosphor-state-manager/systemd_target_parser.cpp \
    -o $OUT/target_parser_fuzzer \
    $LIB_FUZZING_ENGINE

# Copy dictionary
cp $SRC/target_parser_fuzzer.dict $OUT/

# Create seed corpus
zip -q -j $OUT/target_parser_fuzzer_seed_corpus.zip \
    $SRC/phosphor-state-manager/data/phosphor-target-monitor-default.json
