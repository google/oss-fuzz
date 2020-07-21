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

// Fuzz UriQuery.c:
//   uriDissectQueryMallocA
//   uriComposeQueryA

#include <cstddef>
#include <cstdint>
#include <string>
#include <utility>
#include <vector>

using std::string;
#include "uriparser/include/uriparser/Uri.h"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {

  const string query(reinterpret_cast<const char *>(data), size);

  UriQueryListA *query_list = nullptr;
  int item_count = -1;

  const char *query_start = query.c_str();
  const char *query_end = query_start + size;

  // Break a query like "a=b&2=3" into key/value pairs.
  int result =
      uriDissectQueryMallocA(&query_list, &item_count, query_start, query_end);

  if (query_list == nullptr || result != URI_SUCCESS || item_count < 0)
    return 0;

  int chars_required = 0;
  if (uriComposeQueryCharsRequiredA(query_list, &chars_required) != URI_SUCCESS)
    return 0;

  if (!chars_required) {
    uriFreeQueryListA(query_list);
    return 0;
  }

  std::vector<char> buf(chars_required, 0);
  int written = -1;
  // Reverse the process of uriDissectQueryMallocA.
  result = uriComposeQueryA(buf.data(), query_list, chars_required, &written);

  uriFreeQueryListA(query_list);
  return 0;
}
