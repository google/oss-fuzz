// Copyright 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <secmod.h>
#include <stddef.h>
#include <stdint.h>

#include "asn1_fuzzer_template.h"

// Entry point for LibFuzzer.
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  NSSFuzzOneInput<SECKEYPrivateKeyInfo, SEC_QuickDERDecodeItem>(
      SEC_ASN1_GET(SECKEY_PrivateKeyInfoTemplate), data, size);
  NSSFuzzOneInput<SECKEYPrivateKeyInfo, SEC_ASN1DecodeItem>(
      SEC_ASN1_GET(SECKEY_PrivateKeyInfoTemplate), data, size);

  return 0;
}
