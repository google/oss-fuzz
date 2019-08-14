#!/bin/bash -e

bazel build //test/fuzz:fuzz_dash_e --config=fuzz -c opt
cp ./bazel-bin/test/fuzz/fuzz_dash_e $OUT/.
