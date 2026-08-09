#!/bin/bash
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

mkdir tmp
mkdir fonts
unzip PDFExtractTextFuzzer_seed_corpus.zip -d pdfs

#start with a zip of pdfs
#use mutool to extract the fonts and images
#keep the fonts. get rid of the images
#If there's a more efficient way to extract just the fonts, we should implement that

for file in pdfs/*.pdf; do
    echo "$(basename $file)"
    cp "$file" tmp
    cd tmp
    mutool extract "$(basename $file)"
    FONTS=($(find . -name "font-*" -printf '%P\n' 2>/dev/null))
    for fnt in "${FONTS[@]}"; do
        if [ ! -d "../fonts/${fnt##*.}" ]; then
            mkdir "../fonts/${fnt##*.}"
        fi
        cp "$fnt" "../fonts/${fnt##*.}/$(basename $file)-$fnt"
    done
    cd ..
    rm -rf tmp/*
done

if [ -d "fonts/cff" ]; then
    cd fonts/cff
    zip CFFParserFuzzer_seed_corpus.zip *.cff
    mv CFFParserFuzzer_seed_corpus.zip ../..
    cd ../..
fi

if [ -d "fonts/otf" ]; then
    cd fonts/otf
    zip OTFParserFuzzer_seed_corpus.zip *.otf
    mv OTFParserFuzzer_seed_corpus.zip ../.. 
    cd ../.. 
fi

if [ -d "fonts/ttf" ]; then
    cd fonts/ttf
    zip TTFParserFuzzer_seed_corpus.zip *.ttf
    mv TTFParserFuzzer_seed_corpus.zip ../.. 
    cd ../.. 
fi

if [ -d "fonts/cid" ]; then
    cd fonts/cid
    zip CMapParserFuzzer_seed_corpus.zip *.cid
    mv CMapParserFuzzer_seed_corpus.zip ../..
    cd ../.. 
fi

if [ -d "fonts/pfa" ]; then
    cd fonts/pfa
    zip PFAParserFuzzer_seed_corpus.zip *.pfa
    mv PFAParserFuzzer_seed_corpus.zip ../..
    cd ../.. 
fi

rm -rf fonts pdfs tmp
