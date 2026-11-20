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
// The embedded model is fixed; the fuzzer-controlled bytes drive the
// text, token-id and option arguments. Beyond the basic encode/decode
// paths, this harness also drives:
//   * SetEncodeExtraOptions / SetDecodeExtraOptions -> ParseExtraOptions and
//     ApplyExtraOptions (bos/eos/reverse/unk), for both the STL and the
//     SentencePieceText proto output types.
//   * The SentencePieceText / NBestSentencePieceText proto-returning overloads
//     -> PopulateSentencePieceText and the proto branch of ApplyExtraOptions.
//   * Decode() on an arbitrary id stream -> DecodeOptimized bounds,
//     byte-fallback and error handling.
//   * ParallelEncode -> ParallelEncodeInternal / GetChunkOfInput.
//   * SafeIdToPiece and the single-argument Normalize() overload.

#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <memory>
#include <string>
#include <vector>

#include <fuzzer/FuzzedDataProvider.h>
#include "sentencepiece_processor.h"
// SentencePieceText / NBestSentencePieceText, so the proto-returning overloads
// (and the proto-templated ApplyExtraOptions branch) can be exercised.
#include "sentencepiece.pb.h"

// Generated at build time from a small unigram model.
#include "embedded_model.h"

using sentencepiece::NBestSentencePieceText;
using sentencepiece::SentencePieceProcessor;
using sentencepiece::SentencePieceText;

static std::unique_ptr<SentencePieceProcessor> g_processor;

extern "C" int LLVMFuzzerInitialize(int *argc, char ***argv) {
  g_processor = std::make_unique<SentencePieceProcessor>();

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

// Builds a syntactically valid extra-option string ("bos:eos:reverse:unk")
// from a bitmask, so ParseExtraOptions accepts it and the downstream
// ApplyExtraOptions cases are reached. The individual tokens are all valid for
// both the encode and decode option sets.
static std::string BuildExtraOptions(uint8_t bits) {
  static const char *kTokens[] = {"reverse", "bos", "eos", "unk"};
  std::string out;
  for (int i = 0; i < 4; ++i) {
    if (bits & (1u << i)) {
      if (!out.empty()) out.push_back(':');
      out += kTokens[i];
    }
  }
  return out;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  if (!g_processor || size < 2)
    return 0;

  FuzzedDataProvider fdp(data, size);
  const uint8_t ops = fdp.ConsumeIntegral<uint8_t>();
  const uint8_t eopt = fdp.ConsumeIntegral<uint8_t>();
  const uint8_t dopt = fdp.ConsumeIntegral<uint8_t>();
  const uint8_t ctrl = fdp.ConsumeIntegral<uint8_t>();

  // === Extra options ===
  // Set both encode and decode extra options on every input (possibly to the
  // empty string, which clears them) so the per-input behaviour stays
  // deterministic even though the processor object is reused across inputs.
  // The high bit routes a raw fuzzer-controlled token into the parser;
  // otherwise a structurally-valid option string is used.
  if (eopt & 0x80) {
    const std::string raw = fdp.ConsumeBytesAsString(
        fdp.ConsumeIntegralInRange<size_t>(0, 8));
    g_processor->SetEncodeExtraOptions(raw);
  } else {
    g_processor->SetEncodeExtraOptions(BuildExtraOptions(eopt));
  }
  if (dopt & 0x80) {
    const std::string raw = fdp.ConsumeBytesAsString(
        fdp.ConsumeIntegralInRange<size_t>(0, 8));
    g_processor->SetDecodeExtraOptions(raw);
  } else {
    g_processor->SetDecodeExtraOptions(BuildExtraOptions(dopt));
  }

  // An arbitrary token-id stream for Decode() fuzzing. These ids are
  // intentionally unconstrained (negative / out-of-range / byte ids) to
  // exercise DecodeOptimized's bounds and byte-fallback handling.
  const size_t nids = fdp.ConsumeIntegralInRange<size_t>(0, 32);
  std::vector<int> fuzz_ids;
  fuzz_ids.reserve(nids);
  for (size_t i = 0; i < nids; ++i) {
    fuzz_ids.push_back(fdp.ConsumeIntegral<int>());
  }

  const std::string text = fdp.ConsumeRemainingBytesAsString();

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
    // Upstream removed the *AsSerializedProto family; the piece-returning
    // overloads reach the same encode paths. They are [[nodiscard]], so the
    // results are kept alive.
    auto pieces = g_processor->EncodeAsPieces(text);
    (void)pieces;

    auto nb_pieces = g_processor->NBestEncodeAsPieces(text, 2);
    (void)nb_pieces;

    auto sample_pieces = g_processor->SampleEncodeAsPieces(text, -1, 0.5);
    (void)sample_pieces;
  }

  // === Normalization ===
  if (ops & 0x20) {
    std::string normalized;
    g_processor->Normalize(text, &normalized);

    // Normalize with alignment info
    std::string normalized2;
    std::vector<size_t> norm_to_orig;
    g_processor->Normalize(text, &normalized2, &norm_to_orig);

    // Single-argument convenience overload.
    const std::string normalized3 = g_processor->Normalize(text);
    (void)normalized3.size();
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
          // SafeIdToPiece on an in-range id.
          std::string safe;
          g_processor->SafeIdToPiece(id, &safe);
        }
      }
    }
    // SafeIdToPiece on a fuzzer-chosen (possibly out-of-range) id.
    if (!fuzz_ids.empty()) {
      std::string safe;
      g_processor->SafeIdToPiece(fuzz_ids[0], &safe);
    }
  }

  if (ops & 0x80) {
    if (text.size() > 0 && text.size() < 256) {
      auto sampled_pieces = g_processor->SampleEncodeAsPieces(text, 8, 0.5);
      (void)sampled_pieces;
    }
  }

  // === Decode of an arbitrary id stream ===
  // Feed arbitrary ids straight to Decode so DecodeOptimized's range checks,
  // byte-fallback reconstruction and the decode-extra-options copy path are
  // all exercised.
  {
    std::string decoded;
    g_processor->Decode(fuzz_ids, &decoded);
  }

  // === Proto-returning overloads ===
  // These drive PopulateSentencePieceText (piece surfaces, begin/end offsets,
  // byte handling) and the SentencePieceText branch of ApplyExtraOptions, which
  // the vector-returning overloads do not reach.
  {
    SentencePieceText spt;
    if (g_processor->Encode(text, &spt).ok()) {
      // The proto Decode overloads take Span<const absl::string_view> or
      // Span<const int>; feed the ids back to reach Decode(..., spt) ->
      // ApplyExtraOptions<SentencePieceText> on the decode side.
      std::vector<int> proto_ids;
      proto_ids.reserve(spt.pieces_size());
      for (const auto &sp : spt.pieces()) {
        proto_ids.push_back(sp.id());
      }
      SentencePieceText dpt;
      g_processor->Decode(proto_ids, &dpt);
    }

    NBestSentencePieceText nbest_spt;
    g_processor->NBestEncode(text, 3, &nbest_spt);

    SentencePieceText sample_spt;
    g_processor->SampleEncode(text, -1, 0.3, &sample_spt);
  }

  // === Parallel encode ===
  // Exercises ParallelEncodeInternal and GetChunkOfInput. Gated behind a bit so
  // the per-input ThreadPool construction does not dominate runtime, and kept
  // single-threaded for determinism.
  if (ctrl & 0x01) {
    const int chunk_len = fdp.remaining_bytes() == 0
                              ? 4
                              : static_cast<int>((ctrl >> 1) & 0x3f) + 1;
    sentencepiece::ThreadPool pool(1);
    std::vector<std::string> ppieces;
    g_processor->ParallelEncode(text, chunk_len, pool, &ppieces);
    std::vector<int> pids;
    g_processor->ParallelEncode(text, chunk_len, pool, &pids);
  }

  // Reset options to empty so a subsequent input that takes the "clear" branch
  // is not accidentally influenced by this input's state.
  g_processor->SetEncodeExtraOptions("");
  g_processor->SetDecodeExtraOptions("");

  return 0;
}
