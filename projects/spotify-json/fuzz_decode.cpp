// Copyright 2021 Google LLC
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

#include <string>
#include <stdint.h>
#include <spotify/json/codec/number.hpp>
#include <spotify/json/codec/object.hpp>
#include <spotify/json/decode.hpp>
#include <spotify/json/encoded_value.hpp>

namespace {
  struct custom_obj {
    std::string val;
  };
}

template <>
struct spotify::json::default_codec_t<custom_obj> {
  static codec::object_t<custom_obj> codec() {
    auto codec = codec::object<custom_obj>();
    codec.required("x", &custom_obj::val);
    return codec;
  }
};

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  custom_obj obj;
  std::string input(reinterpret_cast<const char*>(data), size);
  spotify::json::try_decode(obj, input);
  return 0;
}
