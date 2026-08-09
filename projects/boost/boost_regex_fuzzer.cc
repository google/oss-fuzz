/* Copyright 2021 Google LLC
Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at
      http://www.apache.org/licenses/LICENSE-2.0
Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/
// From https://svn.boost.org/trac10/ticket/12818
// This fuzz target can likely be enhanced to exercise more code.
// The ideal place for this fuzz target is the boost repository.
#ifdef DEBUG
#include <iostream>
#endif

#include <boost/regex.hpp>
#include <fuzzer/FuzzedDataProvider.h>

namespace {
  void assertPostConditions(boost::match_results<std::string::const_iterator> const& match, boost::regex const& e)
  {
    // See https://www.boost.org/doc/libs/1_71_0/libs/regex/doc/html/boost_regex/ref/regex_match.html
    assert(match.size() == e.mark_count() + 1);
    assert(!match.empty());
    assert(!match.prefix().matched);
    assert(!match.suffix().matched);
  }
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
  FuzzedDataProvider fuzzed_data(Data, Size);
  // First value is length of the regex string
  size_t regex_length = fuzzed_data.ConsumeIntegral<uint8_t>();
  // Second value is regexp string whose length is `regex_length`
  std::string regex_string = fuzzed_data.ConsumeBytesAsString(regex_length);
  try {
    boost::regex e(regex_string);
    // Last value is the text to be matched
    std::string text = fuzzed_data.ConsumeRemainingBytesAsString();

#ifdef DEBUG
    std::cout << "Regexp string: " << regex_string << "Size: " << regex_string.size() << std::endl;
    std::cout << "Text: " << text << "Size: " << text.size() << std::endl;
#endif

    boost::match_results<std::string::const_iterator> what;
    bool match = boost::regex_match(text, what, e,
                       boost::match_default | boost::match_partial);
    if (match)
      assertPostConditions(what, e);
  }
  catch (const std::runtime_error &) {
  }
  return 0;
}
