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

// Fuzzer for the FlatBuffers-based "lite" tokenizer
// (lite/sentencepiece_lite.cc, lite/sentencepiece_model_converters.cc).
// SentencePieceLiteProcessor loads its model from a raw byte buffer that it
// parses in place as a FlatBuffers blob (a double-array trie and vocabulary),
// with pointer arithmetic over the bytes (DoubleArray::transition, LoadLe64,
// StringScanner).
//
// Two complementary modes:
//   * Valid-model mode converts the embedded ModelProto into a lite flatbuffer
//     (exercising ToFlatbuffer in sentencepiece_model_converters.cc) and drives
//     Encode / Normalize / sampling with fuzzed text.
//   * Raw-buffer mode hands arbitrary fuzzer bytes to the constructor to
//     exercise the flatbuffer load/verification and error paths directly.

#include <cstddef>
#include <cstdint>
#include <memory>
#include <string>
#include <vector>

#include <fuzzer/FuzzedDataProvider.h>

#include "sentencepiece_lite.h"
#include "sentencepiece_model_converters.h"
#include "sentencepiece_model.pb.h"

#include "embedded_model.h"

using sentencepiece::lite::SentencePieceLiteProcessor;
using sentencepiece::lite::StatusCode;

// A valid lite flatbuffer, built once from the trusted embedded model.
static std::shared_ptr<std::string> g_valid_buffer;

extern "C" int LLVMFuzzerInitialize(int * /*argc*/, char *** /*argv*/) {
  sentencepiece::ModelProto proto;
  if (proto.ParseFromArray(reinterpret_cast<const char *>(kEmbeddedModelData),
                           static_cast<int>(kEmbeddedModelSize))) {
    auto buffer = sentencepiece::lite::ToFlatbuffer(proto);
    if (buffer.ok()) {
      g_valid_buffer = std::make_shared<std::string>(std::move(buffer).value());
    }
  }
  return 0;
}

static void DriveProcessor(const SentencePieceLiteProcessor &proc,
                           const std::string &text) {
  if (proc.status() != StatusCode::kOk)
    return;

  std::vector<int> ids;
  proc.Encode(text, &ids);

  std::string normalized;
  std::vector<size_t> offsets;
  proc.Normalize(text, &normalized, &offsets);

  proc.CanSkipNormalization(text);

  if (!normalized.empty()) {
    std::vector<int> nids;
    std::vector<std::string_view> pieces;
    proc.EncodeNormalized(normalized, &nids, &pieces);
  }
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  if (size < 1)
    return 0;

  FuzzedDataProvider fdp(data, size);
  const bool use_valid_model = fdp.ConsumeBool();

  if (use_valid_model && g_valid_buffer) {
    // Happy path: a valid model buffer with fuzzed text drives the tokenizer
    // (lite trie lookups, normalization, encoding).
    const std::string text = fdp.ConsumeRemainingBytesAsString();
    SentencePieceLiteProcessor proc(g_valid_buffer);
    DriveProcessor(proc, text);
  } else {
    // Feed arbitrary bytes as the serialized flatbuffer model. The shared_ptr
    // constructor keeps the buffer alive for the processor's lifetime (the
    // buffer is referenced, not copied).
    auto buffer =
        std::make_shared<std::string>(fdp.ConsumeRemainingBytesAsString());
    SentencePieceLiteProcessor proc(buffer);
    // If a mutated buffer happens to load, exercise the tokenizer too.
    DriveProcessor(proc, "hello world");
  }

  return 0;
}
