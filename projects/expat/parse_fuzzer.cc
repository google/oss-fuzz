// Copyright 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <stddef.h>
#include <stdint.h>

#include "expat.h"

#include <functional>
#include <string>

const char* kEncoding =
#if defined(ENCODING_UTF_16)
"UTF-16"
#elif defined(ENCODING_UTF_8)
"UTF-8"
#elif defined(ENCODING_ISO_8859_1)
"ISO-8859-1"
#elif defined(ENCODING_US_ASCII)
"US-ASCII"
#elif defined(ENCODING_UTF_16BE)
"UTF-16BE"
#elif defined(ENCODING_UTF_16LE)
"UTF-16LE"
#else
#error Encoding type is not specified.
#endif
;

// Entry point for LibFuzzer.
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  std::string input(reinterpret_cast<const char*>(data), size);
  auto hash_salt = std::hash<std::string>()(input);

  for (int use_ns = 0; use_ns <= 1; ++use_ns) {
    XML_Parser parser =
        use_ns ? XML_ParserCreateNS(kEncoding, '\n') :
                 XML_ParserCreate(kEncoding);

    // Set a hash salt to prevent MSan from crashing on random bytes generation.
    XML_SetHashSalt(parser, hash_salt);
    XML_Parse(parser, input.c_str(), input.size(), true);
    XML_ParserFree(parser);
  }
  return 0;
}
