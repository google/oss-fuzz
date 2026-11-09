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
#include <algorithm>

#include <opencv2/opencv.hpp>
#include <fuzzer/FuzzedDataProvider.h>

namespace {

bool GetCVImage(const std::string& image_string, const int max_pixels,
                cv::Mat* original_image) {
  if (image_string.empty()) return false;
  
  // Limit input size to prevent OOM
  if (max_pixels > 0 && image_string.size() > static_cast<size_t>(max_pixels) * 3) {
    // Rough estimate: assume up to 3 bytes per pixel for color images
    return false;
  }
  
  std::vector<uchar> raw_data(image_string.size());
  const char* ptr = image_string.data();
  std::copy(ptr, ptr + image_string.size(), raw_data.data());
  try {
    *original_image = cv::imdecode(raw_data, cv::IMREAD_UNCHANGED);
    
    // Check if decoded image exceeds max_pixels limit
    if (max_pixels > 0 && !original_image->empty()) {
      int total_pixels = original_image->rows * original_image->cols;
      if (total_pixels > max_pixels) {
        original_image->release();
        return false;
      }
    }
  } catch (cv::Exception& e) {
    // Explicitly return false on exception
    return false;
  }
  return !original_image->empty();
}

void TestExternalMethods(const cv::Mat& mat) {
  try{
    cv::sum(mat);
  } catch (cv::Exception& e) {}
  try {
    cv::mean(mat);
  } catch (cv::Exception& e) {}
  try {
    cv::trace(mat);
  } catch (cv::Exception& e) {}
}

void TestInternalMethods(const cv::Mat& mat) {
  try {
    mat.t();
  } catch (cv::Exception& e) {}
  try {
    mat.inv();
  } catch (cv::Exception& e) {}
  try {
    mat.diag();
  } catch (cv::Exception& e) {}
}

void TestSplitAndMerge(const cv::Mat& image) {
  std::vector<cv::Mat> split_image(image.channels());
  cv::split(image, split_image);
  if (!split_image.empty()) {
    cv::Mat new_image;
    cv::merge(split_image, new_image);
  }
}

}  // namespace

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  FuzzedDataProvider fuzzed_data_provider(data, size);
  
  // Consume max_pixels with reasonable bounds
  int max_pixels = fuzzed_data_provider.ConsumeIntegralInRange<int>(1, 1000000);
  
  // Limit backup image size using max_pixels
  size_t backup_size = std::min(size, static_cast<size_t>(max_pixels));
  std::vector<uint8_t> image_data(data, data + backup_size);
  cv::Mat backup_image =
      cv::Mat(1, image_data.size(), CV_8UC1, image_data.data());

  const std::string image_string =
      fuzzed_data_provider.ConsumeRemainingBytesAsString();
  cv::Mat original_image;
  
  // Tests the clone method.
  cv::Mat cloned_image = GetCVImage(image_string, max_pixels, &original_image)
                             ? original_image.clone()
                             : backup_image.clone();

  // Test all methods - catch exceptions to prevent crashes
  TestExternalMethods(cloned_image);
  TestInternalMethods(cloned_image);
  TestSplitAndMerge(cloned_image);
  return 0;
}