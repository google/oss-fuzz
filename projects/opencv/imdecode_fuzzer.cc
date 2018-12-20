#include <opencv2/opencv.hpp>
#include <opencv2/imgcodecs/legacy/constants_c.h>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  std::vector<uint8_t> image_data = {data, data + size};
  // TODO: Try other image types than CV_8UC1.
  cv::Mat data_matrix =
      cv::Mat(1, image_data.size(), CV_8UC1, image_data.data());
  try {
    cv::Mat decoded_matrix = cv::imdecode(data_matrix, CV_LOAD_IMAGE_UNCHANGED);
  } catch (cv::Exception e) {
    // Do nothing.
  }
  return 0;
}

