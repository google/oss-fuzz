/* Copyright 2021 Google LLC
Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at
      http://www.apache.org/licenses/LICENSE-2.0
Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

#include "lm/ngram_query.hh"
#include "util/getopt.hh"
#include <iostream>
#include <string>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  char filename[] = "/tmp/libfuzzer";

  FILE *fp = fopen(filename, "wb");
  if (!fp)
    return 0;
  fwrite(data, size, 1, fp);
  fclose(fp);

  lm::ngram::Config config;
  bool sentence_context = true;
  bool print_word = false;
  bool print_line = false;
  bool print_summary = false;
  bool flush = false;

  lm::ngram::QueryPrinter printer(1, print_word, print_line, print_summary,
                                  flush);

  try {
    lm::ngram::ModelType model_type;
    if (RecognizeBinary(filename, model_type)) {
      switch (model_type) {
      case lm::ngram::PROBING:
        Query<lm::ngram::ProbingModel>(filename, config, sentence_context,
                                       printer);
        break;
      case lm::ngram::REST_PROBING:
        Query<lm::ngram::RestProbingModel>(filename, config, sentence_context,
                                           printer);
        break;
      case lm::ngram::TRIE:
        Query<lm::ngram::TrieModel>(filename, config, sentence_context,
                                    printer);
        break;
      case lm::ngram::QUANT_TRIE:
        Query<lm::ngram::QuantTrieModel>(filename, config, sentence_context,
                                         printer);
        break;
      case lm::ngram::ARRAY_TRIE:
        Query<lm::ngram::ArrayTrieModel>(filename, config, sentence_context,
                                         printer);
        break;
      case lm::ngram::QUANT_ARRAY_TRIE:
        Query<lm::ngram::QuantArrayTrieModel>(filename, config,
                                              sentence_context, printer);
        break;
      default:
        std::cerr << "Unrecognized kenlm model type " << model_type
                  << std::endl;
      }
    } else {
      Query<lm::ngram::ProbingModel>(filename, config, sentence_context,
                                     printer);
    }
  } catch (...) {
  }

  std::remove(filename);
  return 0;
}
