// Copyright 2021 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Example of a standalone runner for "fuzz targets".
// It reads all files passed as parameters and feeds their contents
// one by one into the fuzz target (LLVMFuzzerTestOneInput).
// This runner does not do any fuzzing, but allows us to run the fuzz target
// on the test corpus (e.g. "do_stuff_test_data") or on a single file,
// e.g. the one that comes from a bug report.

// This is a fuzz target that times out on every input by infinite looping.
// This is used for testing.
// Build instructions:
// 1. clang++ -fsanitize=fuzzer TimeoutFuzzer.cpp -o timeout_fuzzer
// 2. strip timeout_fuzzer
// The binary is stripped to save space in the git repo.

#include <stddef.h>
#include <stdint.h>

extern "C" int LLVMFuzzerTestOneInput(uint8_t* data, size_t size) {
  while (true)
    ;
  return 0;
}
