// Copyright 2020 Google Inc.
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

#include <cstddef>
#include <cstdint>

#include <opencv2/opencv.hpp>
#include "fuzzer_temp_file.h"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  // Tests reading from a file using cv::FileStorage, which attempts to parse
  // JSON, XML, and YAML, using the first few bytes of a file to determine which
  // type to parse it as.
  const FuzzerTemporaryFile temp_file(data, size);
  cv::FileStorage storage;
  try {
    // TODO: enabling the following crashes right away.
//    storage.open(temp_file.filename(), cv::FileStorage::READ);
  } catch (cv::Exception e) {
    // Do nothing.
  }
  return 0;
}
