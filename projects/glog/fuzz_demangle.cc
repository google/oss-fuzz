// Copyright 2021 Google LLC
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
//
////////////////////////////////////////////////////////////////////////////////

// Hacky
#define _START_GOOGLE_NAMESPACE_ namespace google {
#define _END_GOOGLE_NAMESPACE_ }

#include "demangle.h"

using namespace google;

extern "C" int LLVMFuzzerTestOneInput(const unsigned char *Data, unsigned Size) {
  if (Size >= 4095) {
    return 0;
  }
  char Buffer[Size + 1];
  memcpy(Buffer, Data, Size);
  Buffer[Size] = 0;
  char demangled[4096];
  google::Demangle(Buffer, demangled, Size);
  return 0;
}
