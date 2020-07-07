// Copyright 2019 Google Inc.
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
//
////////////////////////////////////////////////////////////////////////////////

#include "json.pb.h"
#include "json_proto_converter.h"
#include "libprotobuf-mutator/src/libfuzzer/libfuzzer_macro.h"

#include <cstdint>
#include <json/config.h>
#include <json/json.h>
#include <memory>
#include <string>
#include <iostream>
#include <cstddef>
#include <stdint.h>
#include <iostream>

namespace Json {
class Exception;
}

extern "C" int FuzzJson(const char* data_str, size_t size, int32_t hash_settings) {
  Json::CharReaderBuilder builder;

  builder.settings_["failIfExtra"] = hash_settings & (1 << 0);
  builder.settings_["allowComments_"] = hash_settings & (1 << 1);
  builder.settings_["strictRoot_"] = hash_settings & (1 << 2);
  builder.settings_["allowDroppedNullPlaceholders_"] = hash_settings & (1 << 3);
  builder.settings_["allowNumericKeys_"] = hash_settings & (1 << 4);
  builder.settings_["allowSingleQuotes_"] = hash_settings & (1 << 5);
  builder.settings_["failIfExtra_"] = hash_settings & (1 << 6);
  builder.settings_["rejectDupKeys_"] = hash_settings & (1 << 7);
  builder.settings_["allowSpecialFloats_"] = hash_settings & (1 << 8);
  builder.settings_["collectComments"] = hash_settings & (1 << 9);
  builder.settings_["allowTrailingCommas_"] = hash_settings & (1 << 10);

  std::unique_ptr<Json::CharReader> reader(builder.newCharReader());

  Json::Value root;
  try {
    reader->parse(data_str, data_str + size, &root, nullptr);
  } catch (Json::Exception const&) {
  }

  return 0;
}

DEFINE_PROTO_FUZZER(const json_proto::JsonParseAPI &json_proto) {
  json_proto::JsonProtoConverter converter;
  auto s = converter.Convert(json_proto.object_value());
  int32_t hash_settings = json_proto.settings();
  FuzzJson(s.data(), s.size(), hash_settings);
}
