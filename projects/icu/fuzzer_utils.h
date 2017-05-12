// Copyright 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef FUZZER_UTILS_H_
#define FUZZER_UTILS_H_

#include <assert.h>
#include <algorithm>
#include <random>

#include "unicode/unistr.h"
#include "unicode/strenum.h"

#include "unicode/locid.h"
#include "unicode/uchar.h"

struct IcuEnvironment {
  IcuEnvironment() {
    // nothing to initialize yet;
  }
};

// Create RNG and seed it from data.
std::mt19937_64 CreateRng(const uint8_t* data, size_t size) {
  std::mt19937_64 rng;
  std::string str = std::string(reinterpret_cast<const char*>(data), size);
  std::size_t data_hash = std::hash<std::string>()(str);
  rng.seed(data_hash);
  return rng;
}

const icu::Locale& GetRandomLocale(std::mt19937_64* rng) {
  int32_t num_locales = 0;
  const icu::Locale* locales = icu::Locale::getAvailableLocales(num_locales);
  assert(num_locales > 0);
  return locales[(*rng)() % num_locales];
}

icu::UnicodeString UnicodeStringFromUtf8(const uint8_t* data, size_t size) {
  return icu::UnicodeString::fromUTF8(
      icu::StringPiece(reinterpret_cast<const char*>(data), size));
}

icu::UnicodeString UnicodeStringFromUtf32(const uint8_t* data, size_t size) {
  std::vector<UChar32> uchars;
  uchars.resize(size * sizeof(uint8_t) / (sizeof(UChar32)));
  memcpy(uchars.data(), data, uchars.size() * sizeof(UChar32));
  for (size_t i = 0; i < uchars.size(); ++i) {
    uchars[i] = std::min(uchars[i], UCHAR_MAX_VALUE);
  }

  return icu::UnicodeString::fromUTF32(uchars.data(), uchars.size());
}

#endif  // FUZZER_UTILS_H_
