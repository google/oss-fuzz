// Copyright 2023 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
////////////////////////////////////////////////////////////////////////////////

#include "cpp/roaring.hh"
#include "fuzzer/FuzzedDataProvider.h"
#include <vector>

std::vector<uint32_t> ConsumeVecInRange(FuzzedDataProvider &fdp, size_t length,
                                        uint32_t min_value,
                                        uint32_t max_value) {
  std::vector<uint32_t> result = {0};
  result.resize(length);
  std::generate(result.begin(), result.end(), [&]() {
    return fdp.ConsumeIntegralInRange<uint32_t>(min_value, max_value);
  });
  return result;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  FuzzedDataProvider fdp(data, size);
  std::vector<uint32_t> bitmap_data_a = ConsumeVecInRange(fdp, 1000, 0, 500);
  roaring::Roaring a(bitmap_data_a.size(), bitmap_data_a.data());
  a.runOptimize();
  a.shrinkToFit();

  std::vector<uint32_t> bitmap_data_b = ConsumeVecInRange(fdp, 1000, 0, 500);
  roaring::Roaring b(bitmap_data_b.size(), bitmap_data_b.data());
  b.runOptimize();
  b.add(fdp.ConsumeIntegral<uint32_t>());
  b.addChecked(fdp.ConsumeIntegral<uint32_t>());
  b.addRange(fdp.ConsumeIntegral<uint32_t>(), fdp.ConsumeIntegral<uint32_t>());
  // add half of a to b.
  b.addMany(bitmap_data_a.size() / 2, bitmap_data_a.data());
  b.remove(fdp.ConsumeIntegral<uint32_t>());
  b.removeChecked(fdp.ConsumeIntegral<uint32_t>());
  b.removeRange(fdp.ConsumeIntegral<uint32_t>(),
                fdp.ConsumeIntegral<uint32_t>());
  b.removeRangeClosed(fdp.ConsumeIntegral<uint32_t>(),
                      fdp.ConsumeIntegral<uint32_t>());
  b.maximum();
  b.minimum();
  b.contains(fdp.ConsumeIntegral<uint32_t>());
  b.containsRange(fdp.ConsumeIntegral<uint32_t>(),
                  fdp.ConsumeIntegral<uint32_t>());

  uint32_t element = 0;
  a.select(fdp.ConsumeIntegralInRange<uint32_t>(0, 1000), &element);
  a.intersect(b);
  a.jaccard_index(b);
  a.or_cardinality(b);
  a.andnot_cardinality(b);
  a.xor_cardinality(b);
  a.rank(fdp.ConsumeIntegralInRange<uint32_t>(0, 5000));
  a.getSizeInBytes();

  roaring::Roaring c = a & b;
  roaring::Roaring d = a - b;
  roaring::Roaring e = a | b;
  roaring::Roaring f = a ^ b;
  a |= e;
  a &= b;
  a -= c;
  a ^= f;

  volatile bool is_equal = (a == b);

  std::vector<uint32_t> b_as_array = {0};
  b_as_array.resize(b.cardinality());
  b.isEmpty();
  b.toUint32Array(b_as_array.data());

  a.isSubset(b);
  a.isStrictSubset(b);
  b.flip(fdp.ConsumeIntegral<uint32_t>(), fdp.ConsumeIntegral<uint32_t>());
  b.flipClosed(fdp.ConsumeIntegral<uint32_t>(),
               fdp.ConsumeIntegral<uint32_t>());
  b.removeRunCompression();

  // Move/copy constructors
  roaring::Roaring copied = b;
  roaring::Roaring moved = std::move(b);

  // Asignment operatores
  b = copied;
  b = std::move(moved);

  // Safe read from serialized
  std::vector<char> read_buffer = fdp.ConsumeBytes<char>(100);
  std::vector<char> write_buffer = {0};
  try {
    roaring::Roaring read_safely =
        roaring::Roaring::readSafe(read_buffer.data(), read_buffer.size());
    write_buffer.resize(read_safely.getSizeInBytes());
    read_safely.write(write_buffer.data(), fdp.ConsumeBool());
    assert(write_buffer == read_buffer);
  } catch (const std::runtime_error &) {
    // Do nothing.
  }

  f.toString();

  volatile int unused = 0;

  for (roaring::Roaring::const_iterator i = a.begin(); i != a.end(); i++) {
    unused++;
  }

  roaring::Roaring::const_iterator b_iter = b.begin();
  b_iter.equalorlarger(fdp.ConsumeIntegral<uint32_t>());

  return 0;
}
