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
#include <Eigen/Sparse>
#include <Eigen/SparseLU>
#include <Eigen/SparseQR>
#include <vector>

namespace {

static constexpr Eigen::Index kEigenTestMaxSize = 16;

template <typename Scalar>
void fuzzSparse(FuzzedDataProvider* stream) {
  Eigen::Index rows = stream->ConsumeIntegralInRange<Eigen::Index>(1, kEigenTestMaxSize);
  Eigen::Index cols = stream->ConsumeIntegralInRange<Eigen::Index>(1, kEigenTestMaxSize);
  size_t numTriplets = stream->ConsumeIntegralInRange<size_t>(0, rows * cols / 10 + 1);

  typedef Eigen::Triplet<Scalar> T;
  std::vector<T> triplets;
  for (size_t i = 0; i < numTriplets; ++i) {
    Eigen::Index r = stream->ConsumeIntegralInRange<Eigen::Index>(0, rows - 1);
    Eigen::Index c = stream->ConsumeIntegralInRange<Eigen::Index>(0, cols - 1);
    Scalar v;
    if constexpr (std::is_integral_v<Scalar>) {
      v = stream->ConsumeIntegral<Scalar>();
    } else {
      v = stream->ConsumeFloatingPoint<Scalar>();
    }
    triplets.push_back(T(r, c, v));
  }

  Eigen::SparseMatrix<Scalar> mat(rows, cols);
  mat.setFromTriplets(triplets.begin(), triplets.end());

  // Basic operations
  (void)mat.transpose();
  (void)mat.adjoint();
  (void)mat.norm();

  if (rows == cols) {
    // SparseLU
    Eigen::SparseLU<Eigen::SparseMatrix<Scalar>> lu;
    lu.compute(mat);
    if (lu.info() == Eigen::Success) {
      Eigen::Matrix<Scalar, Eigen::Dynamic, 1> b = Eigen::Matrix<Scalar, Eigen::Dynamic, 1>::Random(rows);
      (void)lu.solve(b);
    }
  }

  // SparseQR
  Eigen::SparseQR<Eigen::SparseMatrix<Scalar>, Eigen::COLAMDOrdering<int>> qr;
  qr.compute(mat);
  if (qr.info() == Eigen::Success) {
    Eigen::Matrix<Scalar, Eigen::Dynamic, 1> b = Eigen::Matrix<Scalar, Eigen::Dynamic, 1>::Random(rows);
    (void)qr.solve(b);
  }
}

} // namespace

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  FuzzedDataProvider stream(data, size);

  uint8_t type = stream.ConsumeIntegral<uint8_t>();
  switch (type % 2) {
    case 0:
      fuzzSparse<float>(&stream);
      break;
    case 1:
      fuzzSparse<double>(&stream);
      break;
  }

  return 0;
}
