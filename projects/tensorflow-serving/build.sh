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
# Build script for OSS-Fuzz: compiles the TF Serving JSON tensor fuzzer.

cd /src/tensorflow-serving

# -------------------------------------------------------------------------
# Translate OSS-Fuzz sanitizer flags into Bazel config flags.
# -------------------------------------------------------------------------
EXTRA_BAZEL_FLAGS=""

case "$SANITIZER" in
  address)
    EXTRA_BAZEL_FLAGS="--copt=-fsanitize=address \
                       --copt=-fsanitize-address-use-after-scope \
                       --linkopt=-fsanitize=address"
    ;;
  memory)
    EXTRA_BAZEL_FLAGS="--copt=-fsanitize=memory \
                       --linkopt=-fsanitize=memory"
    ;;
  undefined)
    EXTRA_BAZEL_FLAGS="--copt=-fsanitize=undefined \
                       --linkopt=-fsanitize=undefined"
    ;;
  coverage)
    EXTRA_BAZEL_FLAGS="--copt=-fprofile-instr-generate \
                       --copt=-fcoverage-mapping \
                       --linkopt=-fprofile-instr-generate"
    ;;
esac

# libFuzzer link flag — required for all sanitizer builds.
EXTRA_BAZEL_FLAGS="${EXTRA_BAZEL_FLAGS} \
  --copt=-fsanitize=fuzzer-no-link \
  --linkopt=-fsanitize=fuzzer \
  --copt=-g \
  --strip=never"

# -------------------------------------------------------------------------
# Build the fuzzer target using Bazel.
# -------------------------------------------------------------------------
bazel build \
  --spawn_strategy=standalone \
  --genrule_strategy=standalone \
  --compilation_mode=opt \
  --copt=-O1 \
  --jobs="$(nproc)" \
  --noshow_progress \
  --show_result=0 \
  ${EXTRA_BAZEL_FLAGS} \
  //tensorflow_serving/util:json_tensor_fuzzer

# -------------------------------------------------------------------------
# Copy the fuzzer binary to $OUT (required by OSS-Fuzz).
# -------------------------------------------------------------------------
cp bazel-bin/tensorflow_serving/util/json_tensor_fuzzer \
   "${OUT}/json_tensor_fuzzer"

# -------------------------------------------------------------------------
# Package the seed corpus.
# Corpus files are valid JSON payloads representative of each API endpoint.
# -------------------------------------------------------------------------
mkdir -p /tmp/json_tensor_fuzzer_corpus

# Predict endpoint — "inputs" (columnar) format
cat > /tmp/json_tensor_fuzzer_corpus/predict_inputs_float.json << 'EOF'
{"inputs": [[1.0, 2.0], [3.0, 4.0]]}
EOF

# Predict endpoint — "instances" (row) format
cat > /tmp/json_tensor_fuzzer_corpus/predict_instances_float.json << 'EOF'
{"instances": [1.0, 2.0, 3.0]}
EOF

# Predict endpoint — nested array (triggers GetDenseTensorShape recursion path)
cat > /tmp/json_tensor_fuzzer_corpus/predict_nested.json << 'EOF'
{"inputs": [[[1.0, 2.0], [3.0, 4.0]], [[5.0, 6.0], [7.0, 8.0]]]}
EOF

# Predict endpoint — base64 bytes
cat > /tmp/json_tensor_fuzzer_corpus/predict_b64.json << 'EOF'
{"inputs": [{"b64": "aGVsbG8="}]}
EOF

# Predict endpoint — with signature_name
cat > /tmp/json_tensor_fuzzer_corpus/predict_with_sig.json << 'EOF'
{"signature_name": "serving_default", "inputs": [1.0]}
EOF

# Classify endpoint
cat > /tmp/json_tensor_fuzzer_corpus/classify.json << 'EOF'
{"examples": [{"feature_a": 1.0, "feature_b": [2.0, 3.0]}]}
EOF

# Classify endpoint — with context
cat > /tmp/json_tensor_fuzzer_corpus/classify_context.json << 'EOF'
{"context": {"global": "foo"}, "examples": [{"feature": 1.0}]}
EOF

# Regress endpoint
cat > /tmp/json_tensor_fuzzer_corpus/regress.json << 'EOF'
{"examples": [{"x": 1.0}, {"x": 2.0}]}
EOF

# Empty / edge cases
echo '{}' > /tmp/json_tensor_fuzzer_corpus/empty_object.json
echo '{"inputs": []}' > /tmp/json_tensor_fuzzer_corpus/empty_inputs.json
echo '{"instances": []}' > /tmp/json_tensor_fuzzer_corpus/empty_instances.json

zip -j "${OUT}/json_tensor_fuzzer_seed_corpus.zip" \
    /tmp/json_tensor_fuzzer_corpus/*.json

echo "Build complete. Fuzzer: ${OUT}/json_tensor_fuzzer"
echo "Corpus: ${OUT}/json_tensor_fuzzer_seed_corpus.zip"
