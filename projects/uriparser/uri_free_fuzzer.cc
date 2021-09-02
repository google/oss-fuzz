// Copyright 2020 Google LLC
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
#include <string>

#include "uriparser/include/uriparser/Uri.h"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  std::basic_string<char> fuzz_uri(reinterpret_cast<const char *>(data), size);
  UriParserStateA state;
  UriUriA uriA;
  state.uri = &uriA;
  uriParseUriA(&state, fuzz_uri.c_str());
  uriFreeUriMembersA(&uriA);
  return 0;
}
