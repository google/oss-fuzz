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

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  // Tests filename parsing when opening cv::FileStorage for reading. The file
  // doesn't actually exist, so any logic prediated on successfully opening the
  // file will not be tested.
  //
  // Note that this may actually generate filenames that do exist. If so, this
  // could result in some bugs being difficult to reproduce. If a case doesn't
  // reproduce and looks like a real filename, this may be the cause.
  cv::FileStorage storage;
  try {
    storage.open(std::string(reinterpret_cast<const char*>(data), size),
                 cv::FileStorage::READ);
  } catch (cv::Exception e) {
    // Do nothing.
  }
  return 0;
}
