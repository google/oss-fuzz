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
#include <fuzzer/FuzzedDataProvider.h>

using std::string;
using std::make_pair;
#include "uriparser/include/uriparser/Uri.h"
#include "uriparser/include/uriparser/UriBase.h"

std::vector<std::pair<std::string, std::string>> ToVector(
    UriQueryListA *query_list) {
  std::vector<std::pair<std::string, std::string>> result;
  if (query_list == nullptr) return result;
  for (UriQueryListA *entry = query_list; entry != nullptr;
       entry = entry->next) {
    // The value can be a nullptr.
    result.push_back(std::make_pair(
        entry->key, entry->value == nullptr ? "null" : entry->value));
  }
  uriFreeQueryListA(query_list);
  return result;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  FuzzedDataProvider stream(data, size);
  size_t maxSize = stream.ConsumeIntegral<size_t>();

  const std::string query(reinterpret_cast<const char *>(
      stream.ConsumeRemainingBytes<char>().data()), size);

  UriQueryListA *query_list = nullptr;
  int item_count = -1;

  const char *query_start = query.c_str();
  const char *query_end = query_start + size;

  // Break a query like "a=b&2=3" into key/value pairs.
  int result =
      uriDissectQueryMallocA(&query_list, &item_count, query_start, query_end);

  if (query_list == nullptr || result != URI_SUCCESS) {
    return 0;
  }

  std::vector<char> buf(maxSize, 0);
  int written = -1;
  char *dest = &buf[0];
  // Reverse the process of uriDissectQueryMallocA.
  result = uriComposeQueryA(dest, query_list, maxSize, &written);

  auto queries = ToVector(query_list);

  return 0;
}
