/* Copyright 2023 Google LLC
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
#include <fuzzer/FuzzedDataProvider.h>
#include <iostream>
#include <magic_enum.hpp>
#include <magic_enum_containers.hpp>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  FuzzedDataProvider fdp(data, size);
  const char *fuzz_enum_key1 = fdp.ConsumeRandomLengthString().c_str();
  const char *fuzz_enum_key2 = fdp.ConsumeRandomLengthString().c_str();
  const char *fuzz_enum_key3 = fdp.ConsumeRandomLengthString().c_str();
  const char *fuzz_enum_key4 = fdp.ConsumeRandomLengthString().c_str();
  const char *fuzz_enum_key5 = fdp.ConsumeRandomLengthString().c_str();
  const char *fuzz_enum_key6 = fdp.ConsumeRandomLengthString().c_str();
  const char *fuzz_enum_key7 = fdp.ConsumeRandomLengthString().c_str();
  enum class FuzzEnum : int {
    fuzz_enum_key1 = -5,
    fuzz_enum_key2 = 0,
    fuzz_enum_key3 = 10,
    fuzz_enum_key4 = 11,
    fuzz_enum_key5 = 12,
    fuzz_enum_key6 = 13,
    fuzz_enum_key7 = 14,
  };
  constexpr auto &s7 = magic_enum::enum_values<const FuzzEnum>();

  auto m8 = magic_enum::detail::is_flags_enum<FuzzEnum>();

  auto c1 = magic_enum::enum_cast<FuzzEnum>(fdp.ConsumeIntegral<int>());
  auto c2 = magic_enum::enum_cast<FuzzEnum>(fdp.ConsumeRandomLengthString());
  auto c3 = magic_enum::enum_entries<FuzzEnum>();
  auto c4 = magic_enum::enum_values<FuzzEnum>();
  auto c5 = magic_enum::enum_contains<FuzzEnum>(fdp.ConsumeIntegral<int>());
  auto c6 = magic_enum::enum_contains<FuzzEnum>(fdp.ConsumeIntegral<int>());
  auto c7 = magic_enum::enum_names<FuzzEnum>();
  auto c8 = magic_enum::is_unscoped_enum<FuzzEnum>::value;
  auto c9 = magic_enum::is_scoped_enum<FuzzEnum>::value;
  auto c10 =
      magic_enum::enum_cast<FuzzEnum>(fdp.ConsumeRandomLengthString().c_str());
  auto c11 = magic_enum::enum_cast<FuzzEnum>(fdp.ConsumeRandomLengthString());

  auto e_count = magic_enum::enum_count<FuzzEnum>();

  magic_enum::containers::set e_set{FuzzEnum::fuzz_enum_key1, FuzzEnum::fuzz_enum_key2};
  auto s1 = e_set.empty();
  auto s2 = e_set.size();
  e_set.insert(FuzzEnum::fuzz_enum_key3);
  e_set.clear();

  auto e_bitset = magic_enum::containers::bitset<FuzzEnum>();
  e_bitset.set(FuzzEnum::fuzz_enum_key3);
  auto b0 = e_bitset.size();
  auto b1 = e_bitset.all();
  auto b2 = e_bitset.any();
  auto b3 = e_bitset.none();
  auto b4 = e_bitset.count();

  return 0;
}
