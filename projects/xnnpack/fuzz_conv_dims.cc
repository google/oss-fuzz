/* Copyright 2026 Google LLC
Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at
      http://www.apache.org/licenses/LICENSE-2.0
Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

/*
 * Fuzz target for XNNPACK convolution operator with adversarial dimensions.
 * Complements fuzz_model.cc (which uses hardcoded small dimensions) by
 * exercising the create/reshape paths with fuzzer-generated kernel sizes,
 * channel counts, and padding/stride/dilation values that may trigger
 * integer overflow in weight allocation and stride calculations.
 */

#include <stdint.h>
#include <stdlib.h>

#include <fuzzer/FuzzedDataProvider.h>

#include <xnnpack.h>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  FuzzedDataProvider provider(data, size);

  xnn_status status = xnn_initialize(nullptr);
  if (status != xnn_status_success) {
    return 0;
  }

  /* Fuzzer-generated operator parameters */
  uint32_t input_padding_top = provider.ConsumeIntegralInRange<uint32_t>(0, 128);
  uint32_t input_padding_right = provider.ConsumeIntegralInRange<uint32_t>(0, 128);
  uint32_t input_padding_bottom = provider.ConsumeIntegralInRange<uint32_t>(0, 128);
  uint32_t input_padding_left = provider.ConsumeIntegralInRange<uint32_t>(0, 128);
  uint32_t kernel_height = provider.ConsumeIntegralInRange<uint32_t>(1, 65536);
  uint32_t kernel_width = provider.ConsumeIntegralInRange<uint32_t>(1, 65536);
  uint32_t subsampling_height = provider.ConsumeIntegralInRange<uint32_t>(1, 16);
  uint32_t subsampling_width = provider.ConsumeIntegralInRange<uint32_t>(1, 16);
  uint32_t dilation_height = provider.ConsumeIntegralInRange<uint32_t>(1, 16);
  uint32_t dilation_width = provider.ConsumeIntegralInRange<uint32_t>(1, 16);
  uint32_t groups = provider.ConsumeIntegralInRange<uint32_t>(1, 64);
  uint32_t group_input_channels = provider.ConsumeIntegralInRange<uint32_t>(1, 65536);
  uint32_t group_output_channels = provider.ConsumeIntegralInRange<uint32_t>(1, 65536);
  uint32_t input_pixel_stride = group_input_channels * groups;
  uint32_t output_pixel_stride = group_output_channels * groups;

  float input_scale = provider.ConsumeFloatingPointInRange<float>(0.01f, 10.0f);
  float kernel_scale = provider.ConsumeFloatingPointInRange<float>(0.01f, 10.0f);
  float output_scale = provider.ConsumeFloatingPointInRange<float>(0.01f, 10.0f);

  /* Allocate minimal weight/bias arrays */
  size_t kernel_size = (size_t)kernel_height * kernel_width;
  size_t weights_size = kernel_size * group_input_channels * group_output_channels * groups;

  /* Cap to avoid OOM — we're testing the overflow logic, not memory limits */
  if (weights_size > 1024 * 1024 || weights_size == 0) {
    xnn_deinitialize();
    return 0;
  }

  int8_t *weights = (int8_t *)calloc(weights_size, sizeof(int8_t));
  int32_t *bias = (int32_t *)calloc(group_output_channels * groups, sizeof(int32_t));
  if (!weights || !bias) {
    free(weights);
    free(bias);
    xnn_deinitialize();
    return 0;
  }

  xnn_operator_t op = nullptr;
  status = xnn_create_convolution2d_nhwc_qs8(
      input_padding_top, input_padding_right,
      input_padding_bottom, input_padding_left,
      kernel_height, kernel_width,
      subsampling_height, subsampling_width,
      dilation_height, dilation_width,
      groups,
      group_input_channels, group_output_channels,
      input_pixel_stride, output_pixel_stride,
      -1 /* input zero point */,
      input_scale, kernel_scale,
      weights, bias,
      -1 /* output zero point */,
      output_scale,
      -126 /* output min */, 126 /* output max */,
      0 /* flags */, nullptr, &op);

  if (op) {
    xnn_delete_operator(op);
  }

  free(weights);
  free(bias);
  xnn_deinitialize();
  return 0;
}
