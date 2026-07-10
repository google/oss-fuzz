// Copyright 2026 Google Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Molfile/SDfile text parser fuzzer.
//
// inchi_input_fuzzer feeds an InChI *string* (the InChI->structure direction),
// leaving the MOLfile/SDfile text reader (mol_fmt*.c / readinch.c) at 0%.
// MakeINCHIFromMolfileText parses a Molfile supplied as text and builds an
// InChI from it, exercising the V2000/V3000 connection-table reader directly.

#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "inchi_api.h"

static const size_t kSizeMax = (size_t)-1;

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  if (size == 0 || size == kSizeMax)
    return 0;

  char *moltext = malloc(size + 1);
  if (!moltext)
    return 0;
  memcpy(moltext, data, size);
  moltext[size] = '\0'; // Molfile text must be NUL-terminated

  char options[] = ""; // non-const buffer (API takes char*)

  inchi_Output out;
  memset(&out, 0, sizeof(out));
  MakeINCHIFromMolfileText(moltext, options, &out);
  FreeINCHI(&out);

  free(moltext);
  return 0;
}
