/* Copyright 2026 Google LLC
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
// The ideal place for this fuzz target is the boost repository.
//
// The existing regex fuzz targets (boost_regex_fuzzer, boost_regex_pattern_fuzzer,
// boost_regex_replace_fuzzer) all use boost::regex, i.e.
//   basic_regex<char, regex_traits<char, cpp_regex_traits<char>>>.
// This target instead instantiates the parser over c_regex_traits, which is a
// separate template instantiation with its own syntax_type() implementation and
// is not otherwise exercised. It also varies the syntax_option_type flags, which
// the existing targets leave at their default.

#include <boost/regex.hpp>
#include <fuzzer/FuzzedDataProvider.h>

#include <cstddef>
#include <cstdint>
#include <string>

namespace {

using c_regex_t = boost::basic_regex<char, boost::c_regex_traits<char>>;

// Only the documented bits of syntax_option_type. Feeding the parser undocumented
// bits would not represent a supported way of calling the library.
constexpr unsigned kFlagMask =
    // main syntax group (bits 0-1)
    boost::regbase::basic_syntax_group | boost::regbase::literal |
    // perl/basic subtype options (bits 8-13)
    boost::regbase::no_bk_refs | boost::regbase::no_perl_ex |
    boost::regbase::no_mod_m | boost::regbase::mod_x |
    boost::regbase::mod_s | boost::regbase::no_mod_s |
    // options common to all groups (bits 16-24)
    boost::regbase::no_escape_in_lists | boost::regbase::newline_alt |
    boost::regbase::no_except | boost::regbase::failbit |
    boost::regbase::icase | boost::regbase::collate |
    boost::regbase::nosubs | boost::regbase::save_subexpression_location |
    boost::regbase::no_empty_expressions;

}  // namespace

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
  FuzzedDataProvider fdp(Data, Size);

  const uint32_t raw_flags = fdp.ConsumeIntegral<uint32_t>();
  const auto flags =
      static_cast<c_regex_t::flag_type>(raw_flags & kFlagMask);

  const std::string pattern = fdp.ConsumeRandomLengthString(256);
  const std::string text = fdp.ConsumeRemainingBytesAsString();

  c_regex_t re;
  try {
    re.assign(pattern.data(), pattern.size(), flags);
    // With no_except the parser reports failure through status() instead of
    // throwing, so an unusable expression must not be handed to regex_search.
    if (re.status() == 0) {
      boost::match_results<std::string::const_iterator> what;
      (void)boost::regex_search(text, what, re, boost::match_default);
    }
  } catch (const boost::regex_error &) {
    // Expected for malformed patterns.
  } catch (const std::runtime_error &) {
    // Boost.Regex reports resource limits this way.
  }

  return 0;
}
