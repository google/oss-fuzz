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

// Generates minimal sentencepiece models for fuzzing.
// This is built and run at build time, producing model files.
// Usage: generate_model <output_path> [unigram|bpe|word|char]

#include <fstream>
#include <iostream>
#include <string>

#include "sentencepiece_model.pb.h"

using sentencepiece::ModelProto;
using sentencepiece::TrainerSpec;

static void AddSpecialPieces(ModelProto *model) {
  auto *unk = model->add_pieces();
  unk->set_piece("<unk>");
  unk->set_type(ModelProto::SentencePiece::UNKNOWN);
  unk->set_score(0.0);

  auto *bos = model->add_pieces();
  bos->set_piece("<s>");
  bos->set_type(ModelProto::SentencePiece::CONTROL);
  bos->set_score(0.0);

  auto *eos = model->add_pieces();
  eos->set_piece("</s>");
  eos->set_type(ModelProto::SentencePiece::CONTROL);
  eos->set_score(0.0);
}

static void AddPiece(ModelProto *model, const std::string &piece, float score) {
  auto *sp = model->add_pieces();
  sp->set_piece(piece);
  sp->set_score(score);
}

static void AddBytePiece(ModelProto *model, unsigned char byte) {
  char buf[8];
  snprintf(buf, sizeof(buf), "<0x%02X>", byte);
  auto *sp = model->add_pieces();
  sp->set_piece(buf);
  sp->set_type(ModelProto::SentencePiece::BYTE);
  sp->set_score(-10.0);
}

int main(int argc, char *argv[]) {
  if (argc < 2) {
    std::cerr << "Usage: " << argv[0] << " <output_path> [unigram|bpe|word|char]" << std::endl;
    return 1;
  }

  std::string model_type_str = (argc >= 3) ? argv[2] : "unigram";

  ModelProto model;
  AddSpecialPieces(&model);

  const std::string WS = "\xe2\x96\x81";

  TrainerSpec::ModelType model_type;
  if (model_type_str == "bpe") {
    model_type = TrainerSpec::BPE;
  } else if (model_type_str == "word") {
    model_type = TrainerSpec::WORD;
  } else if (model_type_str == "char") {
    model_type = TrainerSpec::CHAR;
  } else {
    model_type = TrainerSpec::UNIGRAM;
  }

  model.mutable_trainer_spec()->set_model_type(model_type);
  model.mutable_trainer_spec()->set_vocab_size(50);
  model.mutable_trainer_spec()->set_byte_fallback(true);

  // Common vocabulary pieces
  AddPiece(&model, WS, 0.0);
  AddPiece(&model, "a", -0.1);
  AddPiece(&model, "b", -0.2);
  AddPiece(&model, "c", -0.3);
  AddPiece(&model, "d", -0.4);
  AddPiece(&model, "e", -0.1);
  AddPiece(&model, "f", -0.5);
  AddPiece(&model, "g", -0.5);
  AddPiece(&model, "h", -0.3);
  AddPiece(&model, "i", -0.2);
  AddPiece(&model, "l", -0.3);
  AddPiece(&model, "n", -0.2);
  AddPiece(&model, "o", -0.2);
  AddPiece(&model, "r", -0.3);
  AddPiece(&model, "s", -0.2);
  AddPiece(&model, "t", -0.2);
  AddPiece(&model, "u", -0.4);
  AddPiece(&model, "w", -0.5);
  AddPiece(&model, "x", -0.6);
  AddPiece(&model, "y", -0.5);
  AddPiece(&model, "z", -0.7);

  // Subword pieces
  AddPiece(&model, WS + "the", -1.0);
  AddPiece(&model, WS + "a", -1.5);
  AddPiece(&model, WS + "is", -1.8);
  AddPiece(&model, "er", -2.0);
  AddPiece(&model, "in", -2.0);
  AddPiece(&model, "on", -2.0);
  AddPiece(&model, "an", -2.0);
  AddPiece(&model, "th", -1.2);
  AddPiece(&model, "he", -1.3);
  AddPiece(&model, "en", -2.0);
  AddPiece(&model, "re", -2.0);
  AddPiece(&model, "es", -2.2);
  AddPiece(&model, "ing", -1.5);
  AddPiece(&model, "tion", -2.0);
  AddPiece(&model, WS + "hello", -3.0);
  AddPiece(&model, WS + "world", -3.0);
  AddPiece(&model, WS + "test", -3.0);
  AddPiece(&model, WS + "fuzz", -4.0);

  // Byte fallback pieces
  for (int i = 0; i < 256; i++) {
    AddBytePiece(&model, (unsigned char)i);
  }

  // Normalizer spec
  auto *norm_spec = model.mutable_normalizer_spec();
  norm_spec->set_add_dummy_prefix(true);
  norm_spec->set_remove_extra_whitespaces(true);
  norm_spec->set_escape_whitespaces(true);

  // Serialize and write
  std::string serialized;
  model.SerializeToString(&serialized);

  std::ofstream out(argv[1], std::ios::binary);
  if (!out) {
    std::cerr << "Failed to open output file: " << argv[1] << std::endl;
    return 1;
  }
  out.write(serialized.data(), serialized.size());
  out.close();

  std::cout << "Generated " << model_type_str << " model with "
            << model.pieces_size() << " pieces, size=" << serialized.size()
            << " bytes" << std::endl;
  return 0;
}
