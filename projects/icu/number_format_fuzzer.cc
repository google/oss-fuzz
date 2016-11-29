// Copyright 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// Fuzzer for NumberFormat::parse.

#include <stddef.h>
#include <stdint.h>
#include <memory>
#include "fuzzer_utils.h"
#include "unicode/numfmt.h"

IcuEnvironment* env = new IcuEnvironment();

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  UErrorCode status = U_ZERO_ERROR;

  auto rng = CreateRng(data, size);
  const icu::Locale& locale = GetRandomLocale(&rng);

  std::unique_ptr<icu::NumberFormat> fmt(
      icu::NumberFormat::createInstance(locale, status));
  if (U_FAILURE(status)) return 0;

  icu::UnicodeString str(UnicodeStringFromUtf8(data, size));
  icu::Formattable result;
  fmt->parse(str, result, status);

  return 0;
}
