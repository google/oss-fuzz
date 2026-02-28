#!/bin/bash -eu

pip3 install /src/citysense

for fuzzer in /src/citysense/fuzz/fuzz_*.py; do
    compile_python_fuzzer "$fuzzer"
done
