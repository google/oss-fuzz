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
#include <capnp/dynamic.h>
#include <capnp/message.h>
#include <capnp/serialize-text.h>
#include <capnp/test.capnp.h>
#include <kj/exception.h>
#include <kj/string.h>

// Fuzzes the text-format codec (capnp::TextCodec, backed by
// serialize-text.c++ and the same lexer/parser used by SchemaParser).
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* Data, size_t Size) {
  // TextCodec::decode takes a kj::StringPtr — must be NUL-terminated.
  kj::String input = kj::heapString(
      reinterpret_cast<const char*>(Data), Size);

  capnp::TextCodec codec;

  (void)kj::runCatchingExceptions([&]() {
    capnp::MallocMessageBuilder message;
    auto root = message.initRoot<capnp::_::TestAllTypes>();
    codec.decode(input, root);

    // Round-trip: encode the decoded value back to text and stringify the
    // dynamic view to exercise stringify.c++ paths too.
    kj::String reencoded = codec.encode(root.asReader());
    (void)reencoded;
    kj::String stringified = kj::str(root.asReader());
    (void)stringified;
  });

  return 0;
}
