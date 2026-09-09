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

#include <capnp/dynamic.h>
#include <capnp/serialize-packed.h>
#include <capnp/test.capnp.h>
#include <kj/exception.h>
#include <kj/io.h>
#include <kj/string.h>

namespace c = capnproto_test::capnp::test;

// Fuzzes the packed-message decoder path
// (capnp::PackedMessageReader / serialize-packed.c++), which is independent
// from the unpacked path exercised by capnp-llvm-fuzzer-testcase. The
// stringify of both the typed and dynamic root walks every field, exercising
// the reader-side accessors without the noisy KJ_LOG output that the
// gtest-style EXPECT_EQ-laden checkTestMessage helpers produce on
// non-matching input.
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* Data, size_t Size) {
  kj::ArrayPtr<const uint8_t> array(Data, Size);
  kj::ArrayInputStream ais(array);

  (void)kj::runCatchingExceptions([&]() {
    capnp::PackedMessageReader reader(ais);
    auto root = reader.getRoot<c::TestAllTypes>();
    // Touch a handful of primitive and pointer fields. Each access walks
    // the packed-segment cursor to the corresponding offset, exercising
    // the unpacker without the unbounded recursion that a full stringify
    // can hit on a maliciously-shaped message.
    (void)root.getInt32Field();
    (void)root.getUInt64Field();
    (void)root.getFloat64Field();
    (void)root.getTextField();
    (void)root.getDataField();
    (void)root.getStructField().getInt32Field();
    (void)root.getStructList().size();
    (void)root.getEnumList().size();
  });
  return 0;
}
