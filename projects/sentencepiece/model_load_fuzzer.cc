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

// Fuzzer for SentencePiece model loading and post-load operations.
// Feeds arbitrary binary data as a serialized ModelProto, then exercises
// encoding/decoding if the model loads successfully.

#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <string>
#include <unistd.h>
#include <vector>

#include <fuzzer/FuzzedDataProvider.h>
#include "sentencepiece_processor.h"

// Writes `model_data` to a temporary file and loads it through the file-based
// Load() entry point, which exercises src/filesystem.cc (PosixReadableFile /
// ReadAll) and io::LoadModelProto. The in-memory LoadFromSerializedProto path
// below does not go through the filesystem layer.
static void ExerciseFileLoad(const std::string &model_data) {
  char path[] = "/tmp/spm_model_fuzz_XXXXXX";
  const int fd = mkstemp(path);
  if (fd < 0)
    return;
  if (!model_data.empty()) {
    const ssize_t written = write(fd, model_data.data(), model_data.size());
    (void)written;
  }
  close(fd);

  sentencepiece::SentencePieceProcessor file_processor;
  // Return value intentionally ignored; a successful load is further exercised
  // by the in-memory processor below.
  file_processor.Load(path);

  unlink(path);
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  if (size < 4)
    return 0;

  FuzzedDataProvider fdp(data, size);

  // Split data: most goes to model, some to test text
  std::string model_data = fdp.ConsumeRandomLengthString(size);
  std::string test_text = fdp.ConsumeRemainingBytesAsString();

  // Exercise the on-disk loading path (filesystem.cc + io::LoadModelProto).
  ExerciseFileLoad(model_data);

  sentencepiece::SentencePieceProcessor processor;

  // Try loading fuzz data as a serialized model proto
  auto status = processor.LoadFromSerializedProto(model_data);
  if (!status.ok())
    return 0;

  // Model loaded successfully - exercise all major operations

  // Basic encoding
  std::vector<std::string> pieces;
  processor.Encode(test_text, &pieces);

  // Encode to IDs
  std::vector<int> ids;
  processor.Encode(test_text, &ids);

  // Decode from pieces
  if (!pieces.empty()) {
    std::string decoded;
    processor.Decode(pieces, &decoded);
  }

  // Decode from IDs
  if (!ids.empty()) {
    std::string decoded;
    processor.Decode(ids, &decoded);
  }

  // Normalization
  std::string normalized;
  processor.Normalize(test_text, &normalized);

  // Vocabulary operations
  int vocab_size = processor.GetPieceSize();
  if (vocab_size > 0) {
    // PieceToId / IdToPiece round-trip
    for (int i = 0; i < vocab_size && i < 10; i++) {
      std::string piece = processor.IdToPiece(i);
      processor.PieceToId(piece);
      processor.GetScore(i);
      processor.IsUnknown(i);
      processor.IsControl(i);
      processor.IsUnused(i);
      processor.IsByte(i);
    }

    // Try lookup with test_text as a piece
    processor.PieceToId(test_text);
  }

  // Special token IDs
  processor.unk_id();
  processor.bos_id();
  processor.eos_id();
  processor.pad_id();

  // NBest encoding (with small nbest_size to avoid slowness)
  std::vector<std::vector<std::string>> nbest_pieces;
  processor.NBestEncode(test_text, 2, &nbest_pieces);

  // Sample encoding
  std::vector<std::string> sampled;
  processor.SampleEncode(test_text, 1, 0.5, &sampled);

  // Upstream dropped EncodeAsSerializedProto/SampleEncodeAsSerializedProto.
  // The piece-returning overloads reach the same encode paths; they are
  // [[nodiscard]], so keep the results alive.
  const auto encoded_pieces = processor.EncodeAsPieces(test_text);
  const auto sampled_pieces = processor.SampleEncodeAsPieces(test_text, 1, 0.5);
  (void)encoded_pieces.size();
  (void)sampled_pieces.size();

  // Get serialized model
  processor.serialized_model_proto();

  return 0;
}
