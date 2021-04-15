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
#include <iosfwd>

#include <opencv2/opencv.hpp>
#include <fuzzer/FuzzedDataProvider.h>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  const int kMaxXResolution = 6000;
  const int kMaxYResolution = 6000;
  const int kMaxLineThickness = 10;
  const double kMaxFontScale = 10.0;

  FuzzedDataProvider fuzz_provider(data, size);

  int fuzz_font_face = fuzz_provider.PickValueInArray(
      {cv::FONT_HERSHEY_SIMPLEX, cv::FONT_HERSHEY_PLAIN,
       cv::FONT_HERSHEY_DUPLEX, cv::FONT_HERSHEY_COMPLEX,
       cv::FONT_HERSHEY_TRIPLEX, cv::FONT_HERSHEY_COMPLEX_SMALL,
       cv::FONT_HERSHEY_SCRIPT_SIMPLEX, cv::FONT_HERSHEY_SCRIPT_COMPLEX});

  int fuzz_linetype = fuzz_provider.PickValueInArray({
      cv::LINE_8,     // 8-connected line
      cv::LINE_4,     // 4-connected line
      cv::LINE_AA     // anti-aliased line
  });

  double fuzz_font_scale =
      fuzz_provider.ConsumeFloatingPointInRange(0.0, kMaxFontScale);
  int fuzz_width =
      fuzz_provider.ConsumeIntegralInRange<int>(0, kMaxXResolution);
  int fuzz_height =
      fuzz_provider.ConsumeIntegralInRange<int>(0, kMaxYResolution);
  int fuzz_x_pos =
      fuzz_provider.ConsumeIntegralInRange<int>(0, kMaxXResolution);
  int fuzz_y_pos =
      fuzz_provider.ConsumeIntegralInRange<int>(0, kMaxYResolution);
  int fuzz_thickness =
      fuzz_provider.ConsumeIntegralInRange<int>(0, kMaxLineThickness);

  std::vector<uint8_t> color_scalar_vals;
  std::vector<uint8_t> canvas_fill_scalar_vals;

  // Ensure that all 3D vectors are fully populated,
  // even if fuzz_provider is exhausted.
  for (int i = 0; i < 3; i++) {
    color_scalar_vals.insert(color_scalar_vals.begin(),
                             fuzz_provider.ConsumeIntegralInRange(0, 255));
    canvas_fill_scalar_vals.insert(
        canvas_fill_scalar_vals.begin(),
        fuzz_provider.ConsumeIntegralInRange(0, 255));
  }

  cv::Scalar fuzz_color(color_scalar_vals[0], color_scalar_vals[1],
                        color_scalar_vals[2]);
  cv::Scalar fuzz_canvas_fill(canvas_fill_scalar_vals[0],
                              canvas_fill_scalar_vals[1],
                              canvas_fill_scalar_vals[2]);

  cv::Point fuzz_text_pos(fuzz_x_pos, fuzz_y_pos);
  cv::Mat fuzz_canvas(fuzz_height, fuzz_width, CV_8UC3, fuzz_canvas_fill);

  std::basic_string<char> fuzz_annotation =
      fuzz_provider.ConsumeRemainingBytesAsString();

  cv::putText(fuzz_canvas, fuzz_annotation, fuzz_text_pos, fuzz_font_face,
              fuzz_font_scale, fuzz_color, fuzz_thickness, fuzz_linetype);
  return 0;
}
