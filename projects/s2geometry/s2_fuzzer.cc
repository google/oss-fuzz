/*
# Copyright 2020 Google Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
################################################################################
*/

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "s2/s2shapeutil_range_iterator.h"
#include "absl/strings/str_split.h"
#include "absl/strings/string_view.h"

#include "s2/mutable_s2shape_index.h"
#include "s2/s2text_format.h"

// A string-splitter used to help validate the string
// passed to s2
static std::vector<absl::string_view> SplitString(absl::string_view str,
                                                  char separator) {
  std::vector<absl::string_view> result =
      absl::StrSplit(str, separator, absl::SkipWhitespace());
  for (auto &e : result) {
    e = absl::StripAsciiWhitespace(e);
  }
  return result;
}

// Null-terminates the fuzzers input test case
char *null_terminated(const uint8_t *data, size_t size) {
  char *new_str = (char *)malloc(size + 1);
  if (new_str == NULL) {
    return 0;
  }
  memcpy(new_str, data, size);
  new_str[size] = '\0';
  return new_str;
}

// Do a bit of validation that is also done by s2
// We do them here since s2 would terminate if they
// would return false inside s2.
bool isValidFormat(char *nt_string, size_t size) {
  int hash_count = 0;
  for (int i = 0; i < size; i++) {
    if (nt_string[i] == 35) {
      hash_count++;
    }
  }
  if (hash_count != 2) {
    return false;
  }

  std::vector<absl::string_view> strs = SplitString(nt_string, '#');
  size_t strs_size = strs.size();
  if (strs.size() != 3) {
    return false;
  }

  auto index1 = absl::make_unique<MutableS2ShapeIndex>();
  if (s2textformat::MakeIndex(nt_string, &index1) == false) {
    return false;
  }
  return true;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {

  if (size < 5) {
    return 0;
  }

  char *nt_string = null_terminated(data, size);
  if (nt_string == NULL) {
    return 0;
  }
  if (isValidFormat(nt_string, size)) {
    auto index = s2textformat::MakeIndex(nt_string);
    s2shapeutil::RangeIterator it(*index);
    if (!it.done()) {
      it.Next();
    }
  }
  free(nt_string);
  return 0;
}
