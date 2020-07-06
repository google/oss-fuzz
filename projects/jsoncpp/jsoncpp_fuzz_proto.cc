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

DEFINE_PROTO_FUZZER(const json_proto::JsonObject &json_proto) {
  json_proto::JsonProtoConverter converter;
  auto s = converter.Convert(json_proto);
  int32_t hash_settings = converter.GetSettings(json_proto);
  FuzzJson(s.data(), s.size(), hash_settings);
}
