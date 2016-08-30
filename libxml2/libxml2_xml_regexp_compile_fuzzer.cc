// Copyright 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <stddef.h>
#include <stdint.h>

#include <algorithm>
#include <string>
#include <vector>

#include "libxml/parser.h"
#include "libxml/tree.h"
#include "libxml/xmlversion.h"


void ignore (void * ctx, const char * msg, ...) {
  // Error handler to avoid spam of error messages from libxml parser.
}


// Entry point for LibFuzzer.
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  xmlSetGenericErrorFunc(NULL, &ignore);

  std::vector<uint8_t> buffer(size + 1, 0);
  std::copy(data, data + size, buffer.data());

  xmlRegexpPtr x = xmlRegexpCompile(buffer.data());
  if (x)
    xmlRegFreeRegexp(x);

  return 0;
}
