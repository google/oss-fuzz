// Copyright 2020 Google LLC
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

#include "Eigen/Core"

namespace {

static constexpr Eigen::Index kEigenTestMaxSize = 64;
static constexpr Eigen::Index kEigenIndexOne = static_cast<Eigen::Index>(1);

template <typename T>
T ConsumeValue(FuzzedDataProvider* stream) {
  return stream->ConsumeIntegral<T>();
}

template <>
float ConsumeValue(FuzzedDataProvider* stream) {
  return stream->ConsumeFloatingPoint<float>();
}

template <>
double ConsumeValue(FuzzedDataProvider* stream) {
  return stream->ConsumeFloatingPoint<double>();
}

template <>
long double ConsumeValue(FuzzedDataProvider* stream) {
  return stream->ConsumeFloatingPoint<long double>();
}

template <>
std::complex<float> ConsumeValue(FuzzedDataProvider* stream) {
  return std::complex<float>(stream->ConsumeFloatingPoint<float>(),
                             stream->ConsumeFloatingPoint<float>());
}

template <>
std::complex<double> ConsumeValue(FuzzedDataProvider* stream) {
  return std::complex<float>(stream->ConsumeFloatingPoint<double>(),
                             stream->ConsumeFloatingPoint<double>());
}

template <typename MatrixType>
MatrixType GenerateTestMatrix(size_t rows, size_t cols,
                              FuzzedDataProvider* stream) {
  std::vector<typename MatrixType::value_type> test_data(rows * cols);
  for (auto& value : test_data) {
    value = ConsumeValue<typename MatrixType::value_type>(stream);
  }
  Eigen::Map<MatrixType> mapped_map(test_data.data(), rows, cols);
  return MatrixType(mapped_map);
}

template <typename MatrixType>
void basicStuff(const MatrixType& m, FuzzedDataProvider* stream) {
  typedef typename MatrixType::Scalar Scalar;
  typedef Eigen::Matrix<Scalar, MatrixType::RowsAtCompileTime, 1> VectorType;
  typedef Eigen::Matrix<Scalar, MatrixType::RowsAtCompileTime,
                        MatrixType::RowsAtCompileTime>
      SquareMatrixType;

  Eigen::Index rows = m.rows();
  Eigen::Index cols = m.cols();

  MatrixType m1 = GenerateTestMatrix<MatrixType>(rows, cols, stream),
             m2 = GenerateTestMatrix<MatrixType>(rows, cols, stream),
             m3(rows, cols), mzero = MatrixType::Zero(rows, cols),
             square = GenerateTestMatrix<
                 Eigen::Matrix<Scalar, MatrixType::RowsAtCompileTime,
                               MatrixType::RowsAtCompileTime>>(rows, rows,
                                                               stream);
  VectorType v1 = GenerateTestMatrix<VectorType>(rows, 1, stream),
             vzero = VectorType::Zero(rows);
  SquareMatrixType sm1 = SquareMatrixType::Random(rows, rows), sm2(rows, rows);

  Scalar x = ConsumeValue<typename MatrixType::Scalar>(stream);

  Eigen::Index r = stream->ConsumeIntegralInRange(
                   std::min(kEigenIndexOne, rows - 1), rows - 1),
               c = stream->ConsumeIntegralInRange(
                   std::min(kEigenIndexOne, cols - 1), cols - 1);

  m1.coeffRef(r, c) = x;
  m1(r, c) = x;
  v1.coeffRef(r) = x;
  v1(r) = x;
  v1[r] = x;

  Eigen::Index r1 = stream->ConsumeIntegralInRange(
      static_cast<Eigen::Index>(0),
      std::min(static_cast<Eigen::Index>(127), rows - 1));
  x = v1(static_cast<char>(r1));
  x = v1(static_cast<signed char>(r1));
  x = v1(static_cast<unsigned char>(r1));
  x = v1(static_cast<signed short>(r1));
  x = v1(static_cast<unsigned short>(r1));
  x = v1(static_cast<signed int>(r1));
  x = v1(static_cast<unsigned int>(r1));
  x = v1(static_cast<signed long>(r1));
  x = v1(static_cast<unsigned long>(r1));
  x = v1(static_cast<long long int>(r1));
  x = v1(static_cast<unsigned long long int>(r1));

  // now test copying a row-vector into a (column-)vector and conversely.
  square.col(r) = square.row(r).eval();
  Eigen::Matrix<Scalar, 1, MatrixType::RowsAtCompileTime> rv(rows);
  Eigen::Matrix<Scalar, MatrixType::RowsAtCompileTime, 1> cv(rows);
  rv = square.row(r);
  cv = square.col(r);

  cv.transpose();

  m3.real() = m1.real();
  m1 = m2;

  sm2.setZero();
  for (Eigen::Index i = 0; i < rows; ++i) sm2.col(i) = sm1.row(i);

  sm2.setZero();
  for (Eigen::Index i = 0; i < rows; ++i) sm2.col(i).noalias() = sm1.row(i);

  sm2.setZero();
  for (Eigen::Index i = 0; i < rows; ++i) sm2.col(i).noalias() += sm1.row(i);

  sm2.setZero();
  for (Eigen::Index i = 0; i < rows; ++i) sm2.col(i).noalias() -= sm1.row(i);
}

template <typename MatrixType>
void basicStuffComplex(const MatrixType& m, FuzzedDataProvider* stream) {
  typedef typename MatrixType::Scalar Scalar;
  typedef typename Eigen::NumTraits<Scalar>::Real RealScalar;
  typedef Eigen::Matrix<RealScalar, MatrixType::RowsAtCompileTime,
                        MatrixType::ColsAtCompileTime>
      RealMatrixType;

  Eigen::Index rows = m.rows();
  Eigen::Index cols = m.cols();

  RealMatrixType rm1 = GenerateTestMatrix<RealMatrixType>(rows, cols, stream),
                 rm2 = GenerateTestMatrix<RealMatrixType>(rows, cols, stream);
  MatrixType cm(rows, cols);
  cm.real() = rm1;
  cm.imag() = rm2;
  rm1.setZero();
  rm2.setZero();
  rm1 = cm.real();
  rm2 = cm.imag();
  cm.real().setZero();
}

}  // namespace

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  FuzzedDataProvider stream(data, size);

  basicStuff(
      Eigen::MatrixXcf(
          stream.ConsumeIntegralInRange(kEigenIndexOne, kEigenTestMaxSize),
          stream.ConsumeIntegralInRange(kEigenIndexOne, kEigenTestMaxSize)),
      &stream);
  basicStuff(
      Eigen::MatrixXi(
          stream.ConsumeIntegralInRange(kEigenIndexOne, kEigenTestMaxSize),
          stream.ConsumeIntegralInRange(kEigenIndexOne, kEigenTestMaxSize)),
      &stream);
  basicStuff(
      Eigen::MatrixXcd(
          stream.ConsumeIntegralInRange(kEigenIndexOne, kEigenTestMaxSize),
          stream.ConsumeIntegralInRange(kEigenIndexOne, kEigenTestMaxSize)),
      &stream);
  basicStuff(
      Eigen::Matrix<long double, Eigen::Dynamic, Eigen::Dynamic>(
          stream.ConsumeIntegralInRange(kEigenIndexOne, kEigenTestMaxSize),
          stream.ConsumeIntegralInRange(kEigenIndexOne, kEigenTestMaxSize)),
      &stream);
  basicStuffComplex(
      Eigen::MatrixXcf(
          stream.ConsumeIntegralInRange(kEigenIndexOne, kEigenTestMaxSize),
          stream.ConsumeIntegralInRange(kEigenIndexOne, kEigenTestMaxSize)),
      &stream);
  basicStuffComplex(
      Eigen::MatrixXcd(
          stream.ConsumeIntegralInRange(kEigenIndexOne, kEigenTestMaxSize),
          stream.ConsumeIntegralInRange(kEigenIndexOne, kEigenTestMaxSize)),
      &stream);

  return 0;
}
