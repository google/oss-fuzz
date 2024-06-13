/* Copyright 2021 Google LLC
Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at
      http://www.apache.org/licenses/LICENSE-2.0
Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

#include "buffer.h"

extern sdhtml_smartypants(struct buf*, const uint8_t *, size_t); 

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size > 0) {
        struct buf *output_buf;
        output_buf = bufnew(size);
        sdhtml_smartypants(output_buf, data, size);

        bufrelease(output_buf);
    }
    return 0;
}
