// Copyright 2026 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Exercises the prism lexer via pm_serialize_lex.
// Paired with fuzz/fuzz.c which provides LLVMFuzzerTestOneInput -> harness().

#include <prism.h>

void harness(const uint8_t *input, size_t size) {
    pm_buffer_t *buffer = pm_buffer_new();
    pm_serialize_lex(buffer, input, size, NULL);
    pm_buffer_free(buffer);
}
