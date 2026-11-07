#!/bin/bash -eu
# Build script for tflite-micro signal kernel fuzz targets
# Runs inside the oss-fuzz base-builder Docker image.

SRC_ROOT=/src/tflite-micro
DL=$SRC_ROOT/tensorflow/lite/micro/tools/make/downloads

CFLAGS_EXTRA="-I$SRC_ROOT -I$DL/flatbuffers/include -I$DL/gemmlowp -I$DL/ruy"

# Each fuzz target links the real signal/src/ function (gold-standard).
# The targets are small and self-contained — no MicroInterpreter dependency.

# === overlap_add_oob_fuzzer ===
$CXX $CXXFLAGS $CFLAGS_EXTRA $LIB_FUZZING_ENGINE \
  $SRC/signal_overlap_add_fuzzer.cc \
  $SRC_ROOT/signal/src/overlap_add.cc \
  -o $OUT/signal_overlap_add_fuzzer

# === rfft_oob_fuzzer ===
$CXX $CXXFLAGS $CFLAGS_EXTRA $LIB_FUZZING_ENGINE \
  $SRC/signal_rfft_fuzzer.cc \
  -o $OUT/signal_rfft_fuzzer

# === window_oob_fuzzer ===
$CXX $CXXFLAGS $CFLAGS_EXTRA $LIB_FUZZING_ENGINE \
  $SRC/signal_window_fuzzer.cc \
  $SRC_ROOT/signal/src/window.cc \
  -o $OUT/signal_window_fuzzer

# === energy_oob_fuzzer ===
$CXX $CXXFLAGS $CFLAGS_EXTRA $LIB_FUZZING_ENGINE \
  $SRC/signal_energy_fuzzer.cc \
  $SRC_ROOT/signal/src/energy.cc \
  -o $OUT/signal_energy_fuzzer

# === spectral_subtraction_oob_fuzzer ===
$CXX $CXXFLAGS $CFLAGS_EXTRA $LIB_FUZZING_ENGINE \
  $SRC/signal_spectral_subtraction_fuzzer.cc \
  $SRC_ROOT/signal/src/filter_bank_spectral_subtraction.cc \
  -o $OUT/signal_spectral_subtraction_fuzzer

# === pcan_oob_fuzzer ===
$CXX $CXXFLAGS $CFLAGS_EXTRA $LIB_FUZZING_ENGINE \
  $SRC/signal_pcan_fuzzer.cc \
  $SRC_ROOT/signal/src/pcan_argc_fixed.cc \
  $SRC_ROOT/signal/src/msb_32.cc \
  -o $OUT/signal_pcan_fuzzer
