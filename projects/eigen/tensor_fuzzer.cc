// Copyright 2026 Google LLC
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

#include <fuzzer/FuzzedDataProvider.h>
#include <unsupported/Eigen/CXX11/Tensor>

namespace {

static constexpr int kMaxDimensions = 5;
static constexpr int kMaxDimSize = 10;

template <typename Scalar>
void fuzzTensor(FuzzedDataProvider* stream) {
  int numDims = stream->ConsumeIntegralInRange<int>(1, kMaxDimensions);
  Eigen::array<Eigen::Index, kMaxDimensions> dims;
  for (int i = 0; i < kMaxDimensions; ++i) {
    if (i < numDims) {
      dims[i] = stream->ConsumeIntegralInRange<Eigen::Index>(1, kMaxDimSize);
    } else {
      dims[i] = 1;
    }
  }

  // We'll use a fixed rank for simplicity in templating, but varied sizes.
  Eigen::Tensor<Scalar, 3> tensor(
      stream->ConsumeIntegralInRange<Eigen::Index>(1, kMaxDimSize),
      stream->ConsumeIntegralInRange<Eigen::Index>(1, kMaxDimSize),
      stream->ConsumeIntegralInRange<Eigen::Index>(1, kMaxDimSize));
  
  for (Eigen::Index i = 0; i < tensor.size(); ++i) {
    if constexpr (std::is_integral_v<Scalar>) {
      tensor(i) = stream->ConsumeIntegral<Scalar>();
    } else {
      tensor(i) = stream->ConsumeFloatingPoint<Scalar>();
    }
  }

  // Basic operations
  (void)tensor.maximum();
  (void)tensor.minimum();
  (void)tensor.sum();
  (void)tensor.mean();

  // Chipping
  if (tensor.dimension(0) > 0) {
    (void)tensor.chip(0, 0);
  }

  // Shuffling
  Eigen::array<int, 3> shuffle_dims = {1, 0, 2};
  (void)tensor.shuffle(shuffle_dims);

  // Striding
  Eigen::array<Eigen::Index, 3> strides = {2, 1, 1};
  (void)tensor.stride(strides);
}

} // namespace

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  FuzzedDataProvider stream(data, size);

  uint8_t type = stream.ConsumeIntegral<uint8_t>();
  switch (type % 2) {
    case 0:
      fuzzTensor<float>(&stream);
      break;
    case 1:
      fuzzTensor<double>(&stream);
      break;
  }

  return 0;
}
