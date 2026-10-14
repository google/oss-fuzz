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

#include <capnp/schema-parser.h>
#include <capnp/schema.h>
#include <kj/array.h>
#include <kj/exception.h>
#include <kj/string.h>

// Fuzzes the capnp schema-language compiler: lexer, parser, grammar, node
// translator, and SchemaParser glue. The input bytes are wrapped in a
// minimal in-memory SchemaFile so no filesystem (real or virtual) is
// involved — avoiding the lifetime quirks of kj::newInMemoryDirectory().
// After a successful parse, the root types are walked so the schema graph
// is also exercised.
namespace {

class MemSchemaFile final: public capnp::SchemaFile {
public:
  MemSchemaFile(kj::ArrayPtr<const kj::byte> data): data(data) {}

  kj::StringPtr getDisplayName() const override { return "input.capnp"_kj; }

  kj::Array<const char> readContent() const override {
    auto out = kj::heapArray<char>(data.size());
    memcpy(out.begin(), data.begin(), data.size());
    return out.releaseAsBytes().releaseAsChars();
  }

  kj::Maybe<kj::Own<SchemaFile>> import(kj::StringPtr) const override {
    return kj::none;  // no imports
  }

  bool operator==(const SchemaFile& other) const override {
    return this == &other;
  }
  size_t hashCode() const override {
    return reinterpret_cast<size_t>(this);
  }

  void reportError(SourcePos, SourcePos, kj::StringPtr) const override {}

private:
  kj::ArrayPtr<const kj::byte> data;
};

void walk(capnp::Schema schema, int depth) {
  if (depth > 4) return;
  auto proto = schema.getProto();
  (void)proto.getDisplayName();
  if (proto.isStruct()) {
    auto s = schema.asStruct();
    for (auto field : s.getFields()) {
      (void)field.getProto().getName();
      auto type = field.getType();
      if (type.isStruct()) walk(type.asStruct(), depth + 1);
      else if (type.isList()) (void)type.asList().getElementType();
      else if (type.isEnum()) (void)type.asEnum().getEnumerants().size();
      else if (type.isInterface()) walk(type.asInterface(), depth + 1);
    }
  } else if (proto.isInterface()) {
    auto i = schema.asInterface();
    for (auto method : i.getMethods()) {
      (void)method.getProto().getName();
      walk(method.getParamType(), depth + 1);
      walk(method.getResultType(), depth + 1);
    }
  }
}

// parseFile returns a ParsedSchema for a *file* node, not a struct or
// interface. To exercise the schema graph we have to descend into its
// nested declarations.
void walkFile(capnp::ParsedSchema parsed, int depth) {
  if (depth > 4) return;
  for (auto nested : parsed.getAllNested()) {
    walk(nested, depth);
    walkFile(nested, depth + 1);
  }
}

}  // namespace

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* Data, size_t Size) {
  (void)kj::runCatchingExceptions([&]() {
    capnp::SchemaParser parser;
    capnp::ParsedSchema parsed = parser.parseFile(
        kj::heap<MemSchemaFile>(kj::ArrayPtr<const kj::byte>(Data, Size)));
    walkFile(parsed, 0);
  });
  return 0;
}
