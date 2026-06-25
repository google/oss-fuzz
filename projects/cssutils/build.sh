#!/bin/bash -eu
# Copyright 2026 Google LLC
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
#!/bin/bash -eu
# Copyright 2026 Google LLC
# Licensed under the Apache License, Version 2.0 (the "License");

pip install -v cssutils atheris

compile_python_fuzzer \
  $SRC/fuzz_cssutils.py \
  $OUT/cssutils_fuzzer \
  --dict=$SRC/cssutils_fuzzer.dict

cp $SRC/cssutils_fuzzer.dict $OUT/cssutils_fuzzer.dict

mkdir -p $OUT/cssutils_fuzzer_seed_corpus
CORPUS_DIR=$OUT/cssutils_fuzzer_seed_corpus

# 1. Complex Property Values (calc, var, gradients)
cat > "$CORPUS_DIR/complex_values.css" << 'EOF'
:root { --primary: #333; }
body {
  background: linear-gradient(to right, var(--primary), rgba(255,0,0,0.5));
  width: calc(100% - 20px);
  content: url('data:image/svg+xml;utf8,<svg></svg>');
}
EOF

# 2. Deep Selector Chains
cat > "$CORPUS_DIR/deep_selectors.css" << 'EOF'
div.class#id > ul li:first-child:not(.hidden)::before:hover {
  color: red;
}
input[type="text"][data-foo="bar"]:focus-visible {
  border: 1px solid blue;
}
EOF

# 3. Malformed CSS (Error Recovery Test)
cat > "$CORPUS_DIR/malformed.css" << 'EOF'
{ color: ; }
div { background: url(javascript:alert(1)); }
@media { }
@keyframes { 0% {} 100% {} }
p { font-size: calc(10px + 5px; }
EOF

cd $OUT
zip -q -r cssutils_fuzzer_seed_corpus.zip cssutils_fuzzer_seed_corpus/
cd $SRC

echo "=== Build Complete ==="