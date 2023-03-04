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
  /**
   * A bitmap may contain up to 2**32 elements. Later this function will
   * output the content to an array where each element uses 32 bits of storage.
   * That would use 16 GB. Thus this function is bound to run out of memory.
   *
   * Even without the full serialization to a 32-bit array, a bitmap may still use over
   * 512 MB in the normal course of operation: that is to be expected since it can
   * represent all sets of integers in [0,2**32]. This function may hold several
   * bitmaps in memory at once, so it can require gigabytes of memory (without bugs).
   * Hence, unless it has a generous memory capacity, this function will run out of memory
   * almost certainly.
   *
   * For sanity, we may limit the range to, say, 10,000,000 which will use 38 MB or so.
   * With such a limited range, if we run out of memory, then we can almost certain that it
   * has to do with a genuine bug.
   */

  uint32_t range_start = 0;
  uint32_t range_end = 10'000'000;

  /**
   * We are not solely dependent on the range [range_start, range_end) because
   * ConsumeVecInRange below produce integers in a small range starting at 0.
   */

  FuzzedDataProvider fdp(data, size);
  /**
   * The next line was ConsumeVecInRange(fdp, 500, 0, 1000) but it would pick 500
   * values at random from 0, 1000, making almost certain that all of the values are
   * picked. It seems more useful to pick 500 values in the range 0,1000.
   */
  std::vector<uint32_t> bitmap_data_a = ConsumeVecInRange(fdp, 500, 0, 1000);
  roaring::Roaring a(bitmap_data_a.size(), bitmap_data_a.data());
  a.runOptimize();
  a.shrinkToFit();

  std::vector<uint32_t> bitmap_data_b = ConsumeVecInRange(fdp, 500, 0, 1000);
  roaring::Roaring b(bitmap_data_b.size(), bitmap_data_b.data());
  b.runOptimize();
  b.add(fdp.ConsumeIntegralInRange<uint32_t>(range_start, range_end));
  b.addChecked(fdp.ConsumeIntegralInRange<uint32_t>(range_start, range_end));
  b.addRange(fdp.ConsumeIntegralInRange<uint32_t>(range_start, range_end), fdp.ConsumeIntegralInRange<uint32_t>(range_start, range_end));
  // add half of a to b.
  b.addMany(bitmap_data_a.size() / 2, bitmap_data_a.data());
  b.remove(fdp.ConsumeIntegralInRange<uint32_t>(range_start, range_end));
  b.removeChecked(fdp.ConsumeIntegralInRange<uint32_t>(range_start, range_end));
  b.removeRange(fdp.ConsumeIntegralInRange<uint32_t>(range_start, range_end),
                fdp.ConsumeIntegralInRange<uint32_t>(range_start, range_end));
  b.removeRangeClosed(fdp.ConsumeIntegralInRange<uint32_t>(range_start, range_end),
                      fdp.ConsumeIntegralInRange<uint32_t>(range_start, range_end));
  b.maximum();
  b.minimum();
  b.contains(fdp.ConsumeIntegralInRange<uint32_t>(range_start, range_end));
  b.containsRange(fdp.ConsumeIntegralInRange<uint32_t>(range_start, range_end),
                  fdp.ConsumeIntegralInRange<uint32_t>(range_start, range_end));

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
  b.flip(fdp.ConsumeIntegralInRange<uint32_t>(range_start, range_end), fdp.ConsumeIntegralInRange<uint32_t>(range_start, range_end));
  b.flipClosed(fdp.ConsumeIntegralInRange<uint32_t>(range_start, range_end),
               fdp.ConsumeIntegralInRange<uint32_t>(range_start, range_end));
  b.removeRunCompression();

  // Move/copy constructors
  roaring::Roaring copied = b;
  roaring::Roaring moved = std::move(b);

  // Asignment operators
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
  b_iter.equalorlarger(fdp.ConsumeIntegralInRange<uint32_t>(range_start, range_end));

  return 0;
}
