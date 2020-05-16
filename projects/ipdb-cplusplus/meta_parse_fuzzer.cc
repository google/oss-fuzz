//  Copyright 2020 Google Inc.
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

#include <iostream>
#include <string>
#include <cstdint>
#include <stdexcept>

#include "ipdb.h"

#include <rapidjson/document.h>
#include <rapidjson/prettywriter.h>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  /* check json type */
  const std::string s(data, data + size);
  rapidjson::Document document;
  rapidjson::ParseResult pr = document.Parse(s.c_str());
  if ( !pr ) { return 0; }

  try {
    ipdb::MetaData meta;
    meta.Parse(std::string((char *)data, size));
  } catch (const std::runtime_error& e) {
    // Skip logging errors to avoid log spam.
    // std::cout << e.what() << std::endl;
  }
  return 0;
}
