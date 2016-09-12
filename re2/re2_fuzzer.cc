// Copyright (c) 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <stddef.h>
#include <stdint.h>

#include <string>

#include "re2/re2.h"
#include "util/logging.h"

using std::string;

void Test(const string& buffer, const string& pattern,
          const RE2::Options& options) {
  RE2 re(pattern, options);
  if (!re.ok())
    return;

  string m1, m2;
  int i1, i2;
  double d1;

  if (re.NumberOfCapturingGroups() == 0) {
    RE2::FullMatch(buffer, re);
    RE2::PartialMatch(buffer, re);
  } else if (re.NumberOfCapturingGroups() == 1) {
    RE2::FullMatch(buffer, re, &m1);
    RE2::PartialMatch(buffer, re, &i1);
  } else if (re.NumberOfCapturingGroups() == 2) {
    RE2::FullMatch(buffer, re, &i1, &i2);
    RE2::PartialMatch(buffer, re, &m1, &m2);
  }

  re2::StringPiece input(buffer);
  RE2::Consume(&input, re, &m1);
  RE2::FindAndConsume(&input, re, &d1);
  string tmp1(buffer);
  RE2::Replace(&tmp1, re, "zz");
  string tmp2(buffer);
  RE2::GlobalReplace(&tmp2, re, "xx");
  RE2::QuoteMeta(re2::StringPiece(pattern));
}

// Entry point for LibFuzzer.
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  if (size < 1)
    return 0;

  RE2::Options options;

  size_t options_randomizer = 0;
  for (size_t i = 0; i < size; i++)
    options_randomizer += data[i];

  if (options_randomizer & 1)
    options.set_encoding(RE2::Options::EncodingLatin1);

  options.set_posix_syntax(options_randomizer & 2);
  options.set_longest_match(options_randomizer & 4);
  options.set_literal(options_randomizer & 8);
  options.set_never_nl(options_randomizer & 16);
  options.set_dot_nl(options_randomizer & 32);
  options.set_never_capture(options_randomizer & 64);
  options.set_case_sensitive(options_randomizer & 128);
  options.set_perl_classes(options_randomizer & 256);
  options.set_word_boundary(options_randomizer & 512);
  options.set_one_line(options_randomizer & 1024);

  options.set_log_errors(false);

  const char* data_input = reinterpret_cast<const char*>(data);
  {
    string pattern(data_input, size);
    string buffer(data_input, size);
    Test(buffer, pattern, options);
  }

  if (size >= 3) {
    string pattern(data_input, size / 3);
    string buffer(data_input + size / 3, size - size / 3);
    Test(buffer, pattern, options);
  }

  return 0;
}
