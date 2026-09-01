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

#include <capnp/test-util.h>
#include <capnp/compat/json.h>
#include <capnp/message.h>
#include <capnp/test.capnp.h>
#include <kj/exception.h>
#include <kj/string.h>

// Fuzzes the JSON parser/decoder in capnp::JsonCodec. Two complementary
// entry points are exercised:
//   1. decodeRaw -> writes into a json::Value tree; pure parser path.
//   2. decode    -> parser plus the binding logic that maps JSON onto a
//                   typed schema (TestAllTypes) and re-encodes the result.
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* Data, size_t Size) {
  kj::ArrayPtr<const char> input(reinterpret_cast<const char*>(Data), Size);

  capnp::JsonCodec codec;

  (void)kj::runCatchingExceptions([&]() {
    capnp::MallocMessageBuilder rawMessage;
    auto rawRoot = rawMessage.initRoot<capnp::JsonValue>();
    codec.decodeRaw(input, rawRoot);
    // Round-trip the parsed JsonValue to also exercise the encoder.
    kj::String reencoded = codec.encodeRaw(rawRoot.asReader());
    (void)reencoded;
  });

  (void)kj::runCatchingExceptions([&]() {
    capnp::MallocMessageBuilder typedMessage;
    auto root = typedMessage.initRoot<capnp::_::TestAllTypes>();
    codec.decode(input, root);
    codec.setHasMode(capnp::HasMode::NON_DEFAULT);
    kj::String encoded = codec.encode(root.asReader());
    (void)encoded;
  });

  return 0;
}
