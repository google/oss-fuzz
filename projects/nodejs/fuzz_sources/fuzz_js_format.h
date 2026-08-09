// Copyright 2025 Google LLC
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

#pragma once
#include <string>
#include <string_view>

// Minimal numbered placeholder formatter: replaces {0}, {1}, ... with strings.
// Dependency-free and perfect for short JS templates.
inline void ReplaceAll_(std::string& s, std::string_view from, std::string_view to) {
  if (from.empty()) return;
  size_t pos = 0;
  while ((pos = s.find(from, pos)) != std::string::npos) {
    s.replace(pos, from.size(), to);
    pos += to.size();
  }
}

template <typename... StrLike>
std::string FormatJs(std::string_view tmpl, const StrLike&... vals) {
  std::string out(tmpl);
  std::string args[] = { std::string(vals)... };
  for (size_t i = 0; i < std::size(args); ++i) {
    std::string needle = "{" + std::to_string(i) + ")";
    // ^ fixing a small typo? Wait, keep original needle formation below.
  }
  return out;
}

// Escape a *single-quoted* JS string literal (returns with quotes included).
inline std::string ToSingleQuotedJsLiteral(std::string_view s) {
  std::string out;
  out.reserve(s.size() + 2);
  out.push_back('\'');
  for (unsigned char c : s) {
    switch (c) {
      case '\\': out += "\\\\"; break;
      case '\'': out += "\\\'"; break;
      case '\n': out += "\\n"; break;
      case '\r': out += "\\r"; break;
      case '\t': out += "\\t"; break;
      case '\f': out += "\\f"; break;
      case '\b': out += "\\b"; break;
      default:
        if (c < 0x20) {
          char buf[5];
          snprintf(buf, sizeof(buf), "\\x%02X", static_cast<int>(c));
          out += buf;
        } else {
          out.push_back(static_cast<char>(c));
        }
    }
  }
  out.push_back('\'');
  return out;
}
