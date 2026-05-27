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
#include <Eigen/Core>
#include <Eigen/QR>
#include <Eigen/LU>
#include <Eigen/Cholesky>
#include <Eigen/Eigenvalues>
#include <Eigen/SVD>

namespace {

static constexpr Eigen::Index kEigenTestMaxSize = 32;

template <typename Scalar>
void fuzzQR(FuzzedDataProvider* stream) {
  Eigen::Index rows = stream->ConsumeIntegralInRange<Eigen::Index>(1, kEigenTestMaxSize);
  Eigen::Index cols = stream->ConsumeIntegralInRange<Eigen::Index>(1, kEigenTestMaxSize);

  Eigen::Matrix<Scalar, Eigen::Dynamic, Eigen::Dynamic> m(rows, cols);
  for (Eigen::Index i = 0; i < m.size(); ++i) {
    m(i) = stream->ConsumeFloatingPoint<Scalar>();
  }

  // HouseholderQR
  Eigen::HouseholderQR<Eigen::Matrix<Scalar, Eigen::Dynamic, Eigen::Dynamic>> qr(m);
  (void)qr.householderQ();
  (void)qr.matrixQR().template triangularView<Eigen::Upper>();

  // ColPivHouseholderQR
  Eigen::ColPivHouseholderQR<Eigen::Matrix<Scalar, Eigen::Dynamic, Eigen::Dynamic>> cpqr(m);
  (void)cpqr.rank();
  (void)cpqr.isInvertible();

  // FullPivHouseholderQR
  Eigen::FullPivHouseholderQR<Eigen::Matrix<Scalar, Eigen::Dynamic, Eigen::Dynamic>> fpqr(m);
  (void)fpqr.rank();
  (void)fpqr.isInvertible();
}

template <typename Scalar>
void fuzzLU(FuzzedDataProvider* stream) {
  Eigen::Index size = stream->ConsumeIntegralInRange<Eigen::Index>(1, kEigenTestMaxSize);
  Eigen::Matrix<Scalar, Eigen::Dynamic, Eigen::Dynamic> m(size, size);
  for (Eigen::Index i = 0; i < m.size(); ++i) {
    m(i) = stream->ConsumeFloatingPoint<Scalar>();
  }

  // PartialPivLU
  Eigen::PartialPivLU<Eigen::Matrix<Scalar, Eigen::Dynamic, Eigen::Dynamic>> plu(m);
  (void)plu.determinant();
  (void)plu.inverse();

  // FullPivLU
  Eigen::FullPivLU<Eigen::Matrix<Scalar, Eigen::Dynamic, Eigen::Dynamic>> flu(m);
  (void)flu.determinant();
  (void)flu.inverse();
  (void)flu.rank();
}

template <typename Scalar>
void fuzzCholesky(FuzzedDataProvider* stream) {
  Eigen::Index size = stream->ConsumeIntegralInRange<Eigen::Index>(1, kEigenTestMaxSize);
  Eigen::Matrix<Scalar, Eigen::Dynamic, Eigen::Dynamic> m(size, size);
  for (Eigen::Index i = 0; i < m.size(); ++i) {
    m(i) = stream->ConsumeFloatingPoint<Scalar>();
  }

  // LLT
  Eigen::LLT<Eigen::Matrix<Scalar, Eigen::Dynamic, Eigen::Dynamic>> llt(m);
  if (llt.info() == Eigen::Success) {
    (void)llt.matrixL();
    (void)llt.matrixU();
    Eigen::Matrix<Scalar, Eigen::Dynamic, 1> b = Eigen::Matrix<Scalar, Eigen::Dynamic, 1>::Random(size);
    (void)llt.solve(b);
  }

  // LDLT
  Eigen::LDLT<Eigen::Matrix<Scalar, Eigen::Dynamic, Eigen::Dynamic>> ldlt(m);
  if (ldlt.info() == Eigen::Success) {
    (void)ldlt.matrixL();
    (void)ldlt.matrixU();
    (void)ldlt.vectorD();
    (void)ldlt.isPositive();
    (void)ldlt.isNegative();
    Eigen::Matrix<Scalar, Eigen::Dynamic, 1> b = Eigen::Matrix<Scalar, Eigen::Dynamic, 1>::Random(size);
    (void)ldlt.solve(b);
  }
}

template <typename Scalar>
void fuzzEigenvalues(FuzzedDataProvider* stream) {
  Eigen::Index size = stream->ConsumeIntegralInRange<Eigen::Index>(1, kEigenTestMaxSize);
  Eigen::Matrix<Scalar, Eigen::Dynamic, Eigen::Dynamic> m(size, size);
  for (Eigen::Index i = 0; i < m.size(); ++i) {
    m(i) = stream->ConsumeFloatingPoint<Scalar>();
  }

  // EigenSolver
  Eigen::EigenSolver<Eigen::Matrix<Scalar, Eigen::Dynamic, Eigen::Dynamic>> es(m);
  if (es.info() == Eigen::Success) {
    (void)es.eigenvalues();
    (void)es.eigenvectors();
  }

  // SelfAdjointEigenSolver (on a symmetric matrix)
  Eigen::Matrix<Scalar, Eigen::Dynamic, Eigen::Dynamic> symm = m + m.transpose();
  Eigen::SelfAdjointEigenSolver<Eigen::Matrix<Scalar, Eigen::Dynamic, Eigen::Dynamic>> saes(symm);
  if (saes.info() == Eigen::Success) {
    (void)saes.eigenvalues();
    (void)saes.eigenvectors();
  }
}

template <typename Scalar>
void fuzzSVD(FuzzedDataProvider* stream) {
  Eigen::Index rows = stream->ConsumeIntegralInRange<Eigen::Index>(1, kEigenTestMaxSize);
  Eigen::Index cols = stream->ConsumeIntegralInRange<Eigen::Index>(1, kEigenTestMaxSize);
  Eigen::Matrix<Scalar, Eigen::Dynamic, Eigen::Dynamic> m(rows, cols);
  for (Eigen::Index i = 0; i < m.size(); ++i) {
    m(i) = stream->ConsumeFloatingPoint<Scalar>();
  }

  // JacobiSVD
  Eigen::JacobiSVD<Eigen::Matrix<Scalar, Eigen::Dynamic, Eigen::Dynamic>> svd(m, Eigen::ComputeThinU | Eigen::ComputeThinV);
  if (svd.info() == Eigen::Success) {
    (void)svd.singularValues();
    (void)svd.matrixU();
    (void)svd.matrixV();
  }

  // BDCSVD
  Eigen::BDCSVD<Eigen::Matrix<Scalar, Eigen::Dynamic, Eigen::Dynamic>> bdcsvd(m, Eigen::ComputeThinU | Eigen::ComputeThinV);
  if (bdcsvd.info() == Eigen::Success) {
    (void)bdcsvd.singularValues();
    (void)bdcsvd.matrixU();
    (void)bdcsvd.matrixV();
  }
}

} // namespace

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  FuzzedDataProvider stream(data, size);

  uint8_t type = stream.ConsumeIntegral<uint8_t>();
  // 0: QR<float>, 1: QR<double>, 2: LU<float>, 3: LU<double>,
  // 4: Cholesky<float>, 5: Cholesky<double>, 6: Eigenvalues<float>, 7: Eigenvalues<double>,
  // 8: SVD<float>, 9: SVD<double>
  switch (type % 10) {
    case 0:
      fuzzQR<float>(&stream);
      break;
    case 1:
      fuzzQR<double>(&stream);
      break;
    case 2:
      fuzzLU<float>(&stream);
      break;
    case 3:
      fuzzLU<double>(&stream);
      break;
    case 4:
      fuzzCholesky<float>(&stream);
      break;
    case 5:
      fuzzCholesky<double>(&stream);
      break;
    case 6:
      fuzzEigenvalues<float>(&stream);
      break;
    case 7:
      fuzzEigenvalues<double>(&stream);
      break;
    case 8:
      fuzzSVD<float>(&stream);
      break;
    case 9:
      fuzzSVD<double>(&stream);
      break;
  }

  return 0;
}
