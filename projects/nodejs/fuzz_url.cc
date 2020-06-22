/* Copyright 2020 Google Inc.

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
#include <stdlib.h>

#include "node.h"
#include "node_internals.h"
#include "node_url.h"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    node::url::URL url2((char*)data, size);

    return 0;
} 
