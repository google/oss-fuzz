// Copyright 2020 Google Inc.
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

#ifndef JSON_PROTO_CONVERTER_H_
#define JSON_PROTO_CONVERTER_H_

#include <sstream>
#include <string>

#include "json.pb.h"

namespace json_proto {

class JsonProtoConverter {
 public:
  std::string Convert(const json_proto::JsonObject&);
  std::string Convert(const json_proto::ArrayValue&);

 private:
  std::stringstream data_;

  void AppendArray(const json_proto::ArrayValue&);
  void AppendNumber(const json_proto::NumberValue&);
  void AppendObject(const json_proto::JsonObject&);
  void AppendValue(const json_proto::JsonValue&);
};

}  // namespace json_proto

#endif  // TESTING_LIBFUZZER_PROTO_JSON_PROTO_CONVERTER_H_
