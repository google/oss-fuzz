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
 * OSS-Fuzz target: XNNPACK operator reshape indirection-buffer allocation.
 *
 * This fuzzer exercises the create-then-reshape path for operators that
 * allocate indirection buffers (convolution, deconvolution, unpooling).
 * The indirection-buffer size is computed from model-controlled dimensions
 * via unchecked size_t multiplication, which can overflow on 64-bit systems.
 *
 * The fuzzer intentionally does NOT invoke setup/run (which would require
 * multi-GB tensor allocations).  The vulnerability triggers during reshape
 * when the indirection buffer is allocated and populated.
 */

#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <float.h>

#include <fuzzer/FuzzedDataProvider.h>
#include <xnnpack.h>

/* Operator kind selector */
enum OpKind : uint8_t {
  OP_CONV2D = 0,
  OP_DECONV2D = 1,
  OP_UNPOOL2D = 2,
};

static void fuzz_conv2d(FuzzedDataProvider& provider) {
  uint32_t kernel_h = provider.ConsumeIntegralInRange<uint32_t>(1, 65535);
  uint32_t kernel_w = provider.ConsumeIntegralInRange<uint32_t>(1, 65535);
  uint32_t stride_h = provider.ConsumeIntegralInRange<uint32_t>(1, 65535);
  uint32_t stride_w = provider.ConsumeIntegralInRange<uint32_t>(1, 65535);
  uint32_t dilation_h = provider.ConsumeIntegralInRange<uint32_t>(1, 255);
  uint32_t dilation_w = provider.ConsumeIntegralInRange<uint32_t>(1, 255);
  uint32_t groups = provider.ConsumeIntegralInRange<uint32_t>(1, 65535);
  size_t group_input_channels = provider.ConsumeIntegralInRange<size_t>(1, 65535);
  size_t group_output_channels = provider.ConsumeIntegralInRange<size_t>(1, 65535);
  uint32_t padding_top = provider.ConsumeIntegralInRange<uint32_t>(0, 255);
  uint32_t padding_left = provider.ConsumeIntegralInRange<uint32_t>(0, 255);
  uint32_t padding_bottom = provider.ConsumeIntegralInRange<uint32_t>(0, 255);
  uint32_t padding_right = provider.ConsumeIntegralInRange<uint32_t>(0, 255);

  size_t batch_size = provider.ConsumeIntegralInRange<size_t>(1, UINT32_MAX);
  size_t input_height = provider.ConsumeIntegralInRange<size_t>(1, UINT32_MAX);
  size_t input_width = provider.ConsumeIntegralInRange<size_t>(1, UINT32_MAX);

  /*
   * Allocate a minimal kernel and bias.  The packing function reads from
   * these during create, so they must be valid, but their content does not
   * matter for triggering the reshape overflow.  We only need
   * groups * group_output_channels * kernel_h * kernel_w * group_input_channels
   * elements, but that product itself could be huge, so cap the allocation
   * at a small fixed size and let the packing read from a small buffer
   * (create will either succeed with a small valid subset or return an error;
   * either way we proceed to reshape if create succeeds).
   *
   * For the overflow to trigger we need large INPUT dimensions, not large
   * kernels.  So keep channels/kernel small to make create succeed, and let
   * the fuzzer supply large reshape dimensions.
   */
  const size_t kernel_elems = (size_t)kernel_h * kernel_w *
                              group_input_channels * group_output_channels;
  /* Cap to avoid OOM during create; if kernel is too large for our fixed
   * buffer, create will read OOB (benign under ASAN, create may fail). */
  static float kernel_buf[4096];
  static float bias_buf[4096];
  memset(kernel_buf, 0, sizeof(kernel_buf));
  memset(bias_buf, 0, sizeof(bias_buf));

  if (kernel_elems > sizeof(kernel_buf) / sizeof(float)) {
    /* Reduce to fit */
    group_input_channels = 1;
    group_output_channels = 1;
    groups = 1;
    kernel_h = 1;
    kernel_w = 1;
  }

  xnn_operator_t op = nullptr;
  xnn_status status = xnn_create_convolution2d_nhwc_f32(
      padding_top, padding_right, padding_bottom, padding_left,
      kernel_h, kernel_w, stride_h, stride_w, dilation_h, dilation_w,
      groups, group_input_channels, group_output_channels,
      groups * group_input_channels,   /* input_channel_stride */
      groups * group_output_channels,  /* output_channel_stride */
      kernel_buf, bias_buf,
      -FLT_MAX, FLT_MAX, 0 /* flags */, nullptr /* weights_cache */,
      &op);

  if (status != xnn_status_success) {
    return;
  }

  /* Reshape: this is where the indirection-buffer overflow can occur. */
  size_t workspace_size = 0, output_height = 0, output_width = 0;
  xnn_reshape_convolution2d_nhwc_f32(
      op, batch_size, input_height, input_width,
      &workspace_size, &output_height, &output_width,
      nullptr /* threadpool */);

  xnn_delete_operator(op);
}

static void fuzz_deconv2d(FuzzedDataProvider& provider) {
  uint32_t kernel_h = provider.ConsumeIntegralInRange<uint32_t>(1, 65535);
  uint32_t kernel_w = provider.ConsumeIntegralInRange<uint32_t>(1, 65535);
  uint32_t stride_h = provider.ConsumeIntegralInRange<uint32_t>(1, 65535);
  uint32_t stride_w = provider.ConsumeIntegralInRange<uint32_t>(1, 65535);
  uint32_t dilation_h = provider.ConsumeIntegralInRange<uint32_t>(1, 255);
  uint32_t dilation_w = provider.ConsumeIntegralInRange<uint32_t>(1, 255);
  uint32_t groups = provider.ConsumeIntegralInRange<uint32_t>(1, 65535);
  size_t group_input_channels = provider.ConsumeIntegralInRange<size_t>(1, 65535);
  size_t group_output_channels = provider.ConsumeIntegralInRange<size_t>(1, 65535);

  size_t batch_size = provider.ConsumeIntegralInRange<size_t>(1, UINT32_MAX);
  size_t input_height = provider.ConsumeIntegralInRange<size_t>(1, UINT32_MAX);
  size_t input_width = provider.ConsumeIntegralInRange<size_t>(1, UINT32_MAX);
  uint32_t adj_h = provider.ConsumeIntegralInRange<uint32_t>(0, stride_h - 1);
  uint32_t adj_w = provider.ConsumeIntegralInRange<uint32_t>(0, stride_w - 1);

  const size_t kernel_elems = (size_t)kernel_h * kernel_w *
                              group_input_channels * group_output_channels;
  static float kernel_buf[4096];
  static float bias_buf[4096];
  memset(kernel_buf, 0, sizeof(kernel_buf));
  memset(bias_buf, 0, sizeof(bias_buf));

  if (kernel_elems > sizeof(kernel_buf) / sizeof(float)) {
    group_input_channels = 1;
    group_output_channels = 1;
    groups = 1;
    kernel_h = 1;
    kernel_w = 1;
  }

  xnn_operator_t op = nullptr;
  xnn_status status = xnn_create_deconvolution2d_nhwc_f32(
      0, 0, 0, 0,  /* output padding */
      kernel_h, kernel_w, stride_h, stride_w, dilation_h, dilation_w,
      groups, group_input_channels, group_output_channels,
      groups * group_input_channels,
      groups * group_output_channels,
      kernel_buf, bias_buf,
      -FLT_MAX, FLT_MAX, 0, nullptr, &op);

  if (status != xnn_status_success) {
    return;
  }

  size_t output_height = 0, output_width = 0;
  xnn_reshape_deconvolution2d_nhwc_f32(
      op, batch_size, input_height, input_width, adj_h, adj_w,
      &output_height, &output_width, nullptr);

  xnn_delete_operator(op);
}

static void fuzz_unpool2d(FuzzedDataProvider& provider) {
  uint32_t pool_h = provider.ConsumeIntegralInRange<uint32_t>(1, 65535);
  uint32_t pool_w = provider.ConsumeIntegralInRange<uint32_t>(1, 65535);
  uint32_t padding_top = provider.ConsumeIntegralInRange<uint32_t>(0, 255);
  uint32_t padding_left = provider.ConsumeIntegralInRange<uint32_t>(0, 255);
  uint32_t padding_bottom = provider.ConsumeIntegralInRange<uint32_t>(0, 255);
  uint32_t padding_right = provider.ConsumeIntegralInRange<uint32_t>(0, 255);

  size_t batch_size = provider.ConsumeIntegralInRange<size_t>(1, UINT32_MAX);
  size_t input_height = provider.ConsumeIntegralInRange<size_t>(1, UINT32_MAX);
  size_t input_width = provider.ConsumeIntegralInRange<size_t>(1, UINT32_MAX);
  size_t channels = provider.ConsumeIntegralInRange<size_t>(1, 65535);

  xnn_operator_t op = nullptr;
  xnn_status status = xnn_create_unpooling2d_nhwc_x32(
      padding_top, padding_right, padding_bottom, padding_left,
      pool_h, pool_w, 0 /* flags */, &op);

  if (status != xnn_status_success) {
    return;
  }

  size_t output_height = 0, output_width = 0;
  xnn_reshape_unpooling2d_nhwc_x32(
      op, batch_size, input_height, input_width,
      channels, channels, channels,
      &output_height, &output_width, nullptr);

  xnn_delete_operator(op);
}

static bool xnn_inited = false;

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  /* Need at least 1 byte for op selector + enough for dimensions */
  if (size < 52) {
    return 0;
  }

  if (!xnn_inited) {
    xnn_status status = xnn_initialize(nullptr);
    if (status != xnn_status_success) {
      return 0;
    }
    xnn_inited = true;
  }

  FuzzedDataProvider provider(data, size);

  uint8_t op_kind = provider.ConsumeIntegral<uint8_t>() % 3;
  switch (op_kind) {
    case OP_CONV2D:
      fuzz_conv2d(provider);
      break;
    case OP_DECONV2D:
      fuzz_deconv2d(provider);
      break;
    case OP_UNPOOL2D:
      fuzz_unpool2d(provider);
      break;
  }

  return 0;
}
