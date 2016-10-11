// Copyright 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef ASN1_FUZZER_TEMPLATE_H_
#define ASN1_FUZZER_TEMPLATE_H_

#include <nspr.h>
#include <nss.h>
#include <secasn1.h>
#include <secder.h>
#include <secitem.h>
#include <secport.h>
#include <stddef.h>
#include <stdint.h>

template <typename DestinationType,
          SECStatus (*DecodeFunction)(PLArenaPool*,
                                      void*,
                                      const SEC_ASN1Template*,
                                      const SECItem*)>
void NSSFuzzOneInput(const SEC_ASN1Template* the_template,
                     const uint8_t* data,
                     size_t size) {
  DestinationType* destination = new DestinationType();
  memset(destination, 0, sizeof(DestinationType));

  PLArenaPool* arena = PORT_NewArena(DER_DEFAULT_CHUNKSIZE);
  if (!arena) {
    delete destination;
    return;
  }

  SECItem source;
  source.type = siBuffer;
  source.data = static_cast<unsigned char*>(const_cast<uint8_t*>(data));
  source.len = static_cast<unsigned int>(size);

  DecodeFunction(arena, destination, the_template, &source);

  PORT_FreeArena(arena, PR_FALSE);
  delete destination;
}

#endif  // ASN1_FUZZER_TEMPLATE_H_
