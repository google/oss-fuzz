// Copyright 2019 Google LLC
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
#include <cstdlib>
#include <string>

#include "Eigen/Core"

using ::Eigen::Matrix;
using ::Eigen::Dynamic;
using ::Eigen::Lower;
using ::Eigen::Upper;

int ConsumeNextInt(const uint8_t** data, size_t* size) {
  if (*size < sizeof(int)) {
    return 0;
  }
  int result;
  memcpy(&result, *data, sizeof(int));
  *size -= sizeof(int);
  *data += sizeof(int);
  return result;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  const size_t rows = static_cast<size_t>(ConsumeNextInt(&data, &size));
  const size_t columns = static_cast<size_t>(ConsumeNextInt(&data, &size));

  if (rows == 0 || columns == 0) {
    return 0;
  }
  if (rows > 1024 || columns > 1024) {
    return 0;
  }

  // We can do this same fuzz test with other templated types. Here, we just use
  // an int.
  Matrix<int, Dynamic, 1> vec(rows);
  for (size_t i = 0; i < rows; ++i) {
    vec(i) = ConsumeNextInt(&data, &size);
  }
  Matrix<int, Dynamic, Dynamic> matrix(rows, columns);
  for (int i = 0; i < rows; ++i) {
    for (int j = 0; j < columns; ++j) {
      matrix(i, j) = ConsumeNextInt(&data, &size);
    }
  }

  matrix.template triangularView<Lower>().solve(vec);
  matrix.template triangularView<Upper>().solve(vec);
  matrix.conjugate().template triangularView<Lower>().solve(vec);
  matrix.conjugate().template triangularView<Upper>().solve(vec);
  matrix.transpose().template triangularView<Lower>().solve(vec);
  matrix.transpose().template triangularView<Upper>().solve(vec);

  return 0;
}
