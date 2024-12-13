#!/bin/bash -eu
# Copyright 2024 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
################################################################################

export GGML_NO_OPENMP=1
sed -i 's/:= c++/:= ${CXX}/g' ./Makefile
sed -i 's/:= cc/:= ${CC}/g' ./Makefile
# Avoid function that forks + starts instance of gdb.
sed -i 's/ggml_print_backtrace();//g' ./ggml/src/ggml.c

# Remove statefulness during fuzzing.
sed -i 's/static bool is_first_call/bool is_first_call/g' ./ggml/src/ggml.c

# Patch callocs to avoid allocating large chunks.
sed -i 's/ggml_calloc(size_t num, size_t size) {/ggml_calloc(size_t num, size_t size) {\nif ((num * size) > 9000000) {GGML_ABORT("calloc err");}\n/g' -i ./ggml/src/ggml.c

# Patch a potentially unbounded loop that causes timeouts
sed -i 's/ok = ok \&\& (info->n_dims <= GGML_MAX_DIMS);/ok = ok \&\& (info->n_dims <= GGML_MAX_DIMS);\nif (!ok) {fclose(file); gguf_free(ctx); return NULL;}/g' ./ggml/src/ggml.c

UNAME_M=amd642 UNAME_p=amd642 LLAMA_NO_METAL=1 make -j$(nproc) llama-gguf llama-server

# Convert models into header files so we can use them for fuzzing.
xxd -i models/ggml-vocab-bert-bge.gguf > model_header_bge.h
xxd -i models/ggml-vocab-llama-bpe.gguf > model_header_bpe.h
xxd -i models/ggml-vocab-llama-spm.gguf > model_header_spm.h
xxd -i models/ggml-vocab-qwen2.gguf > model_header_qwen2.h
xxd -i models/ggml-vocab-command-r.gguf > model_header_command_r.h
xxd -i models/ggml-vocab-aquila.gguf > model_header_aquila.h
xxd -i models/ggml-vocab-gpt-2.gguf > model_header_gpt_2.h
xxd -i models/ggml-vocab-baichuan.gguf > model_header_baichuan.h
xxd -i models/ggml-vocab-deepseek-coder.gguf > model_header_deepseek_coder.h
xxd -i models/ggml-vocab-falcon.gguf > model_header_falcon.h


mkdir myos
find ./ggml/ -name *.o -exec cp {} myos/ \;
find ./src/ -name *.o -exec cp {} myos/ \;
find ./common/ -name *.o -exec cp {} myos/ \;
OBJ_FILES="myos/*.o"
FLAGS="-std=c++11 -Iggml/include -Iggml/src -Iinclude -Isrc -Icommon -I./ -DNDEBUG -DGGML_USE_LLAMAFILE"

$CXX $LIB_FUZZING_ENGINE $CXXFLAGS ${FLAGS} ${OBJ_FILES} fuzzers/fuzz_json_to_grammar.cpp -o $OUT/fuzz_json_to_grammar
$CXX $LIB_FUZZING_ENGINE $CXXFLAGS ${FLAGS} ${OBJ_FILES} fuzzers/fuzz_apply_template.cpp -o $OUT/fuzz_apply_template
$CXX $LIB_FUZZING_ENGINE $CXXFLAGS ${FLAGS} ${OBJ_FILES} fuzzers/fuzz_grammar.cpp -o $OUT/fuzz_grammar

$CXX $LIB_FUZZING_ENGINE $CXXFLAGS ${FLAGS} ${OBJ_FILES} \
    -Wl,--wrap,abort fuzzers/fuzz_load_model.cpp -o $OUT/fuzz_load_model

$CXX $LIB_FUZZING_ENGINE $CXXFLAGS ${FLAGS} ${OBJ_FILES} \
    -Wl,--wrap,abort fuzzers/fuzz_inference.cpp -o $OUT/fuzz_inference

$CXX $LIB_FUZZING_ENGINE $CXXFLAGS ${FLAGS} ${OBJ_FILES} \
    -Wl,--wrap,abort fuzzers/fuzz_structured.cpp -o $OUT/fuzz_structured

$CXX $LIB_FUZZING_ENGINE $CXXFLAGS ${FLAGS} ${OBJ_FILES} \
    -Wl,--wrap,abort fuzzers/fuzz_structurally_created.cpp -o $OUT/fuzz_structurally_created

# Prepare some dicts and seeds
./llama-gguf dummy.gguf w
mkdir $SRC/load-model-corpus
mv dummy.gguf $SRC/load-model-corpus/
zip -j $OUT/fuzz_load_model_seed_corpus.zip $SRC/load-model-corpus/*
cp $OUT/fuzz_load_model_seed_corpus.zip $OUT/fuzz_inference_seed_corpus.zip

echo "[libfuzzer]" > $OUT/fuzz_load_model.options
echo "detect_leaks=0" >> $OUT/fuzz_load_model.options

cp $OUT/fuzz_load_model.options $OUT/fuzz_inference.options
cp $OUT/fuzz_load_model.options $OUT/fuzz_structured.options
cp $OUT/fuzz_load_model.options $OUT/fuzz_structurally_created.options
cp fuzzers/llama.dict $OUT/fuzz_load_model.dict
cp fuzzers/llama.dict $OUT/fuzz_inference.dict
cp fuzzers/llama.dict $OUT/fuzz_grammar.dict
cp fuzzers/llama.dict $OUT/fuzz_structured.dict
cp fuzzers/llama.dict $OUT/fuzz_json_to_grammar.dict

if [ "$FUZZING_ENGINE" != "afl" ]
then
    $CXX -Wl,--wrap,abort $LIB_FUZZING_ENGINE $CXXFLAGS ${FLAGS} ${OBJ_FILES} -DFUZZ_BGE fuzzers/fuzz_tokenizer.cpp -o $OUT/fuzz_tokenizer_bge
    $CXX -Wl,--wrap,abort $LIB_FUZZING_ENGINE $CXXFLAGS ${FLAGS} ${OBJ_FILES} -DFUZZ_BPE  fuzzers/fuzz_tokenizer.cpp -o $OUT/fuzz_tokenizer_bpe
    $CXX -Wl,--wrap,abort $LIB_FUZZING_ENGINE $CXXFLAGS ${FLAGS} ${OBJ_FILES} -DFUZZ_SPM  fuzzers/fuzz_tokenizer.cpp -o $OUT/fuzz_tokenizer_spm
    $CXX -Wl,--wrap,abort $LIB_FUZZING_ENGINE $CXXFLAGS ${FLAGS} ${OBJ_FILES} -DFUZZ_COMMAND_R  fuzzers/fuzz_tokenizer.cpp -o $OUT/fuzz_tokenizer_command_r
    $CXX -Wl,--wrap,abort $LIB_FUZZING_ENGINE $CXXFLAGS ${FLAGS} ${OBJ_FILES} -DFUZZ_AQUILA  fuzzers/fuzz_tokenizer.cpp -o $OUT/fuzz_tokenizer_aquila
    $CXX -Wl,--wrap,abort $LIB_FUZZING_ENGINE $CXXFLAGS ${FLAGS} ${OBJ_FILES} -DFUZZ_QWEN2  fuzzers/fuzz_tokenizer.cpp -o $OUT/fuzz_tokenizer_qwen2
    $CXX -Wl,--wrap,abort $LIB_FUZZING_ENGINE $CXXFLAGS ${FLAGS} ${OBJ_FILES} -DFUZZ_GPT_2  fuzzers/fuzz_tokenizer.cpp -o $OUT/fuzz_tokenizer_gpt_2
    $CXX -Wl,--wrap,abort $LIB_FUZZING_ENGINE $CXXFLAGS ${FLAGS} ${OBJ_FILES} -DFUZZ_BAICHUAN  fuzzers/fuzz_tokenizer.cpp -o $OUT/fuzz_tokenizer_baichuan
    $CXX -Wl,--wrap,abort $LIB_FUZZING_ENGINE $CXXFLAGS ${FLAGS} ${OBJ_FILES} -DFUZZ_DEEPSEEK_CODER  fuzzers/fuzz_tokenizer.cpp -o $OUT/fuzz_tokenizer_deepseek_coder
    $CXX -Wl,--wrap,abort $LIB_FUZZING_ENGINE $CXXFLAGS ${FLAGS} ${OBJ_FILES} -DFUZZ_FALCON  fuzzers/fuzz_tokenizer.cpp -o $OUT/fuzz_tokenizer_falcon
fi
