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

#include "gtest/gtest.h"
#include "fuzztest/fuzztest.h"

namespace codelab {
namespace {

TEST(EscapingTest, EscapingEmptyStringReturnsEmptyString) {
  EXPECT_EQ(Escape(""), "");
}

TEST(EscapingTest, UnescapingEmptyStringReturnsEmptyString) {
  EXPECT_EQ(Unescape(""), "");
}

TEST(EscapingTest, EscapingPlainStringIsReturnedAsIs) {
  EXPECT_EQ(Escape("plain text"), "plain text");
}

TEST(EscapingTest, UnescapingPlainStringIsReturnedAsIs) {
  EXPECT_EQ(Unescape("plain text"), "plain text");
}

TEST(EscapingTest, EscapingReplacesSpecialCharacters) {
  EXPECT_EQ(Escape("two\nlines"), "two\\nlines");
  EXPECT_EQ(Escape("back\\slash"), "back\\\\slash");
}

TEST(EscapingTest, UnescapingReplacesEscapeSequences) {
  EXPECT_EQ(Unescape("two\\nlines"), "two\nlines");
  EXPECT_EQ(Unescape("back\\\\slash"), "back\\slash");
}

// Comment out the following fuzz tests:

void UnescapingEscapedStringGivesOriginal(std::string_view s) {
  EXPECT_EQ(s, Unescape(Escape(s)));
}
FUZZ_TEST(EscapingTest, UnescapingEscapedStringGivesOriginal);

void EscapingAStringNeverTriggersUndefinedBehavior(std::string_view s) {
  Escape(s);
}
FUZZ_TEST(EscapingTest, EscapingAStringNeverTriggersUndefinedBehavior);

void UnescapingAStringNeverTriggersUndefinedBehavior(std::string_view s) {
   Unescape(s);
}
FUZZ_TEST(EscapingTest, UnescapingAStringNeverTriggersUndefinedBehavior);

}  // namespace
}  // namespace codelab
