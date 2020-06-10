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

#include "absl/strings/str_join.h"
#include "absl/strings/str_split.h"
#include "absl/strings/numbers.h"
#include "absl/strings/str_cat.h"


extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
	// First 4 bytes for float, next 4 for double, next 4 for int, next 1 for boolean, then atleast 1 for string 1
	size_t min_length = 14 * sizeof(uint8_t);
	if (size < min_length)
		return 0;
	std::string str (reinterpret_cast<const char*>(data), size);
	std::string float_str, double_str, int_str, bool_str, str1, str2;
	float_str = str.substr(0, 4);
	double_str = str.substr(4, 4);
	int_str = str.substr(8, 4);
	bool_str = str.substr(12, 1);
	str1 = str.substr(13, (sizeof(str) - 12)/2);
	str2 = str.substr(13 + str1.length());

	float float_value;
	double double_value;
	int int_value;
	bool bool_value;
	if (!absl::SimpleAtof(float_str, &float_value))
		return 0;
	if (!absl::SimpleAtod(double_str, &double_value))
		return 0;
	if (!absl::SimpleAtoi(int_str, &int_value))
		return 0;
	if (!absl::SimpleAtob(bool_str, &bool_value))
		return 0;

	absl::StrAppend(&str1, str2);
	std::string str_result = absl::StrCat(str1, float_value, double_value, int_value, bool_value);
	std::vector<std::string> v = absl::StrSplit(str_result, ".");
	str_result = absl::StrJoin(v, ".");
	return 0;
}