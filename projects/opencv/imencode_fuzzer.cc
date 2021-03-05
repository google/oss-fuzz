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
  std::vector<uint8_t> image_data = {data, data + size};
  cv::Mat data_matrix =
      cv::Mat(1, image_data.size(), CV_8UC1, image_data.data());
  try {
    std::vector<uchar> buffer;
    cv::imencode(".tiff", data_matrix, buffer);
  } catch (cv::Exception e) {
    // Do nothing.
  }
  return 0;
}
