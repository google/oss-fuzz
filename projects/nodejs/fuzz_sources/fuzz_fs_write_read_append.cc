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

// Combines write/read/append operations on a temp file with fuzzed data.
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  FuzzedDataProvider fdp(data, size);

  const size_t len0 = fdp.ConsumeIntegralInRange<size_t>(0, 4096);
  const std::string w1 = fdp.ConsumeRandomLengthString(len0);
  const std::string w2 = fdp.ConsumeRemainingBytesAsString();

  static constexpr std::string_view kTemplate = R"(
const fs = require('fs');

try { fs.rmSync('/tmp/fuzz-file', { force: true }); } catch (e) {}

fs.writeFileSync('/tmp/fuzz-file', {0});

try {
  const fd = fs.openSync('/tmp/fuzz-file', 'r+');
  const buffer = Buffer.alloc(1024);
  fs.readSync(fd, buffer, 0, buffer.length, 0);
  fs.closeSync(fd);
} catch (e) {}

const textToAppend = {1};
try {
  fs.appendFileSync('/tmp/fuzz-file', textToAppend, { encoding: 'utf8' });
  fs.readFileSync('/tmp/fuzz-file', { encoding: 'utf8' });
} catch (e) {}
)";

  const std::string js =
      FormatJs(kTemplate, ToSingleQuotedJsLiteral(w1), ToSingleQuotedJsLiteral(w2));

  fuzz::IsolateScope iso;
  if (!iso.ok()) return 0;
  fuzz::RunEnvString(iso.isolate(), js.c_str());
  return 0;
}
