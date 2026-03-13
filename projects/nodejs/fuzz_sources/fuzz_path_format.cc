// Copyright 2025 Google LLC
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

#include <cstdint>
#include <string>
#include "fuzzer/FuzzedDataProvider.h"
#include "fuzz_common.h"
#include "fuzz_js_format.h"

namespace{ constexpr const char* kSrc=R"JS((function(x){ const path=require('path'); try{ path.format(x); }catch{} }))JS"; }

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  FuzzedDataProvider fdp(data, size);

  const std::string a0 = fdp.ConsumeRemainingBytesAsString();

  fuzz::IsolateScope iso;
  if (!iso.ok()) return 0;

  const std::string js = FormatJs(
      "try { ({0})({1}); } catch (e) {}",
      std::string(kSrc),
      ToSingleQuotedJsLiteral(a0));
  fuzz::RunEnvString(iso.isolate(), js.c_str());
  return 0;
}
