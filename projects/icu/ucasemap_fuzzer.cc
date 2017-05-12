// Copyright 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// Fuzzer for ucasemap.

#include <stddef.h>
#include <stdint.h>
#include <memory>
#include "fuzzer_utils.h"
#include "unicode/ucasemap.h"

IcuEnvironment* env = new IcuEnvironment();

template<typename T>
using deleted_unique_ptr = std::unique_ptr<T,std::function<void(T*)>>;

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  UErrorCode status = U_ZERO_ERROR;

  auto rng = CreateRng(data, size);
  const icu::Locale& locale = GetRandomLocale(&rng);
  uint32_t open_flags = static_cast<uint32_t>(rng());

  deleted_unique_ptr<UCaseMap> csm(
      ucasemap_open(locale.getName(), open_flags, &status),
      [](UCaseMap* map) { ucasemap_close(map); });

  if (U_FAILURE(status))
    return 0;

  int32_t dst_size = size * 2;
  std::unique_ptr<char[]> dst(new char[dst_size]);
  auto src = reinterpret_cast<const char*>(data);

  switch (rng() % 4) {
    case 0: ucasemap_utf8ToLower(csm.get(), dst.get(), dst_size, src, size,
                &status);
            break;
    case 1: ucasemap_utf8ToUpper(csm.get(), dst.get(), dst_size, src, size,
                &status);
            break;
    case 2: ucasemap_utf8ToTitle(csm.get(), dst.get(), dst_size, src, size,
                &status);
            break;
    case 3: ucasemap_utf8FoldCase(csm.get(), dst.get(), dst_size, src, size,
                &status);
            break;
  }

  return 0;
}

