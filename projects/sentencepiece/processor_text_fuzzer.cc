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

// Fuzzer that loads a valid pre-built sentencepiece model (embedded in
// the binary as a byte array) and then fuzzes all encoding, decoding,
// normalization, and vocabulary operations with fuzz-derived text input.

#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <memory>
#include <string>
#include <vector>

#include <fuzzer/FuzzedDataProvider.h>
#include "sentencepiece_processor.h"

// Generated at build time by: xxd -i processor_text_fuzzer_model
#include "embedded_model.h"

static std::unique_ptr<sentencepiece::SentencePieceProcessor> g_processor;

extern "C" int LLVMFuzzerInitialize(int *argc, char ***argv) {
  g_processor = std::make_unique<sentencepiece::SentencePieceProcessor>();

  // Load the model from the embedded byte array
  std::string model_data(
      reinterpret_cast<const char *>(kEmbeddedModelData),
      kEmbeddedModelSize);
  auto status = g_processor->LoadFromSerializedProto(model_data);
  if (!status.ok()) {
    fprintf(stderr, "Failed to load embedded model: %s\n",
            status.ToString().c_str());
    abort();
  }

  return 0;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  if (!g_processor || size < 2)
    return 0;

  FuzzedDataProvider fdp(data, size);
  uint8_t ops = fdp.ConsumeIntegral<uint8_t>();
  std::string text = fdp.ConsumeRemainingBytesAsString();

  // === Core encoding operations ===
  if (ops & 0x01) {
    // Encode to pieces (strings)
    std::vector<std::string> pieces;
    g_processor->Encode(text, &pieces);

    // Decode back from pieces
    if (!pieces.empty()) {
      std::string decoded;
      g_processor->Decode(pieces, &decoded);
    }
  }

  if (ops & 0x02) {
    // Encode to IDs
    std::vector<int> ids;
    g_processor->Encode(text, &ids);

    // Decode back from IDs
    if (!ids.empty()) {
      std::string decoded;
      g_processor->Decode(ids, &decoded);
    }
  }

  // === Advanced encoding operations ===
  if (ops & 0x04) {
    // NBest encoding - use small nbest to avoid being too slow
    std::vector<std::vector<std::string>> nbest_pieces;
    g_processor->NBestEncode(text, 3, &nbest_pieces);

    // NBest encode to IDs
    std::vector<std::vector<int>> nbest_ids;
    g_processor->NBestEncode(text, 3, &nbest_ids);
  }

  if (ops & 0x08) {
    // Sample encoding with various alpha values
    std::vector<std::string> sampled;
    g_processor->SampleEncode(text, -1, 0.5, &sampled);

    std::vector<int> sampled_ids;
    g_processor->SampleEncode(text, -1, 0.1, &sampled_ids);
  }

  if (ops & 0x10) {
    // Encode as serialized proto (exercises protobuf serialization path)
    auto serialized = g_processor->EncodeAsSerializedProto(text);
    (void)serialized;

    auto nb_serialized = g_processor->NBestEncodeAsSerializedProto(text, 2);
    (void)nb_serialized;

    auto sample_serialized = g_processor->SampleEncodeAsSerializedProto(text, -1, 0.5);
    (void)sample_serialized;
  }

  // === Normalization ===
  if (ops & 0x20) {
    std::string normalized;
    g_processor->Normalize(text, &normalized);

    // Normalize with alignment info
    std::string normalized2;
    std::vector<size_t> norm_to_orig;
    g_processor->Normalize(text, &normalized2, &norm_to_orig);
  }

  // === Vocabulary operations ===
  if (ops & 0x40) {
    // PieceToId with fuzz text
    g_processor->PieceToId(text);

    // Try splitting text into substrings and looking them up
    if (text.size() > 2) {
      for (size_t i = 0; i < text.size() && i < 8; i++) {
        std::string sub = text.substr(0, i + 1);
        int id = g_processor->PieceToId(sub);
        if (id >= 0 && id < g_processor->GetPieceSize()) {
          g_processor->IdToPiece(id);
          g_processor->GetScore(id);
          g_processor->IsUnknown(id);
          g_processor->IsControl(id);
          g_processor->IsUnused(id);
          g_processor->IsByte(id);
        }
      }
    }
  }

  // === Entropy calculation ===
  if (ops & 0x80) {
    if (text.size() > 0 && text.size() < 256) {
      float entropy = g_processor->CalculateEntropy(text, 0.5);
      (void)entropy;
    }
  }

  return 0;
}
