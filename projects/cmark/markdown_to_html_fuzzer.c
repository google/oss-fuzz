// Copyright 2017 Google Inc. All Rights Reserved.
// Licensed under the Apache License, Version 2.0 (the "License");
#include <stdint.h>
#include <stdlib.h>
#include "cmark.h"

int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  int options = 0;
  if (size > sizeof(options)) {
    /* First 4 bytes of input are treated as options */
    int options = *(const int *)data;

    /* Mask off valid option bits */
    options = options & (CMARK_OPT_SOURCEPOS | CMARK_OPT_HARDBREAKS | CMARK_OPT_SAFE | CMARK_OPT_NOBREAKS | CMARK_OPT_NORMALIZE | CMARK_OPT_VALIDATE_UTF8 | CMARK_OPT_SMART);

    /* Remainder of input is the markdown */
    const char *markdown = (const char *)(data + sizeof(options));
    char *html = cmark_markdown_to_html(markdown, size - sizeof(options), options);
    free(html);
  }
  return 0;
}
