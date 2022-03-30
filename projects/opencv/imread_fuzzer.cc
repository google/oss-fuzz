#include <cstddef>
#include <cstdint>
#include <unistd.h>

#include <opencv2/opencv.hpp>
#include "fuzzer_temp_file.h"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  const FuzzerTemporaryFile file(data, size);
  try {
    cv::Mat matrix = cv::imread(file.filename());
  } catch (cv::Exception e) {
    // Do nothing.
  }
  return 0;
}

