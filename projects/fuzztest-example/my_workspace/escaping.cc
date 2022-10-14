// Copyright 2022 Google LLC
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

#include "./escaping.h"

namespace codelab {

std::string Escape(std::string_view str) {
  std::string result;
  for (size_t i = 0; i < str.size(); ++i) {
    switch (str[i]) {
      case '\n':
        result.push_back('\\');
        result.push_back('n');
        break;
      case '\r':
        result.push_back('\\');
        result.push_back('r');
        break;
      case '\t':
        result.push_back('\\');
        result.push_back('t');
        break;
      case '\\':
        result.push_back('\\');
        result.push_back('\\');
        break;
      default:
        result.push_back(str[i]);
        break;
    }
  }
  return result;
}

std::string Unescape(std::string_view str) {
  std::string result;
  for (size_t i = 0; i < str.size(); ++i) {
    if (str[i] == '\\') {
      ++i;
      switch (str[i]) {
        case 'n':
          result.push_back('\n');
          break;
        case 't':
          result.push_back('\t');
          break;
        case '\\':
          result.push_back('\\');
          break;
        default:
          break;
      }
    } else {
      result.push_back(str[i]);
    }
  }
  return result;
}

}  // namespace codelab
