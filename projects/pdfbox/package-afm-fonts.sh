#/!bin/bash
# Copyright 2025 Google LLC
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
mkdir afm-tmp

FONTS=($(find . -name "*.afm" -printf '%P\n' 2>/dev/null))
for fnt in "${FONTS[@]}"; do
    cp "$fnt" afm-tmp
done

cd afm-tmp
zip AFMParserFuzzer_seed_corpus.zip *.afm
mv AFMParserFuzzer_seed_corpus.zip ..
cd ..

rm -rf afm-tmp
