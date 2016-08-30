// Copyright 2015 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <stddef.h>
#include <stdint.h>

#include "libxml/parser.h"

void ignore (void* ctx, const char* msg, ...) {
  // Error handler to avoid spam of error messages from libxml parser.
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  xmlSetGenericErrorFunc(NULL, &ignore);

  if (auto doc = xmlReadMemory(reinterpret_cast<const char*>(data),
                               static_cast<int>(size), "noname.xml", NULL, 0)) {
    xmlFreeDoc(doc);
  }

  return 0;
}
