// Copyright 2020 Google Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
////////////////////////////////////////////////////////////////////////////////

#include <string> 

#include "absl/strings/ascii.h"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
	if (size < 10)
    {
        return 0;
    }
    std::string str (reinterpret_cast<const char*>(data), size);
	
    for (int i = 0; i < 10; i++) {
        absl::ascii_isalpha(str[i]);
        absl::ascii_isalnum(str[i]);
        absl::ascii_isspace(str[i]);
        absl::ascii_ispunct(str[i]);
        absl::ascii_isblank(str[i]);
        absl::ascii_iscntrl(str[i]);
        absl::ascii_isxdigit(str[i]);
        absl::ascii_isdigit(str[i]);
        absl::ascii_isprint(str[i]);
        absl::ascii_isgraph(str[i]);
        absl::ascii_isupper(str[i]);
        absl::ascii_islower(str[i]);
        absl::ascii_isascii(str[i]);
        absl::ascii_tolower(str[i]);
        absl::ascii_toupper(str[i]);
    }
    absl::AsciiStrToUpper(&str);
    absl::AsciiStrToLower(&str);
    absl::StripLeadingAsciiWhitespace(&str);
    absl::StripTrailingAsciiWhitespace(&str);
    absl::StripAsciiWhitespace(&str);

	return 0;
}