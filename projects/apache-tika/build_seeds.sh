#!/bin/bash -eu
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

mkdir ${SRC}/seeds
#This packages the unit test files based on file extension from within the Tika project
#we could also pull in other seeds from other parser projects.

find ${SRC}/project-parent/tika -name "*-webm.noext" -print0 | xargs -0 zip -u ${SRC}/seeds/AudioVideoParsersFuzzer_seed_corpus.zip
find ${SRC}/project-parent/tika -name "*-mkv.noext" -print0 | xargs -0 zip -u ${SRC}/seeds/AudioVideoParsersFuzzer_seed_corpus.zip
find ${SRC}/project-parent/tika -name "*.aif" -print0 | xargs -0 zip -u ${SRC}/seeds/AudioVideoParsersFuzzer_seed_corpus.zip
find ${SRC}/project-parent/tika -name "*.au" -print0 | xargs -0 zip -u ${SRC}/seeds/AudioVideoParsersFuzzer_seed_corpus.zip
find ${SRC}/project-parent/tika -name "*.flv" -print0 | xargs -0 zip -u ${SRC}/seeds/AudioVideoParsersFuzzer_seed_corpus.zip
find ${SRC}/project-parent/tika -name "*.m4a" -print0 | xargs -0 zip -u ${SRC}/seeds/AudioVideoParsersFuzzer_seed_corpus.zip
find ${SRC}/project-parent/tika -name "*.mkv" -print0 | xargs -0 zip -u ${SRC}/seeds/AudioVideoParsersFuzzer_seed_corpus.zip
find ${SRC}/project-parent/tika -name "*.mp3" -print0 | xargs -0 zip -u ${SRC}/seeds/AudioVideoParsersFuzzer_seed_corpus.zip
find ${SRC}/project-parent/tika -name "*.wav" -print0 | xargs -0 zip -u ${SRC}/seeds/AudioVideoParsersFuzzer_seed_corpus.zip


find ${SRC}/project-parent/tika -name "*.Z" -print0 | xargs -0 zip -u ${SRC}/seeds/CompressorParserFuzzer_seed_corpus.zip
find ${SRC}/project-parent/tika -name "*.bz2" -print0 | xargs -0 zip -u ${SRC}/seeds/CompressorParserFuzzer_seed_corpus.zip
find ${SRC}/project-parent/tika -name "*.gz" -print0 | xargs -0 zip -u ${SRC}/seeds/CompressorParserFuzzer_seed_corpus.zip
find ${SRC}/project-parent/tika -name "*.tbz2" -print0 | xargs -0 zip -u ${SRC}/seeds/CompressorParserFuzzer_seed_corpus.zip
find ${SRC}/project-parent/tika -name "*.tgz" -print0 | xargs -0 zip -u ${SRC}/seeds/CompressorParserFuzzer_seed_corpus.zip
find ${SRC}/project-parent/tika -name "*.zst" -print0 | xargs -0 zip -u ${SRC}/seeds/CompressorParserFuzzer_seed_corpus.zip

find ${SRC}/project-parent/tika -name "*.html" -print0 | xargs -0 zip ${SRC}/seeds/HtmlParserFuzzer_seed_corpus.zip

find ${SRC}/project-parent/tika -name "*.avif" -print0 | xargs -0 zip -u ${SRC}/seeds/ImageParsersFuzzer_seed_corpus.zip
find ${SRC}/project-parent/tika -name "*.bmp" -print0 | xargs -0 zip -u ${SRC}/seeds/ImageParsersFuzzer_seed_corpus.zip
find ${SRC}/project-parent/tika -name "*.bpg" -print0 | xargs -0 zip -u ${SRC}/seeds/ImageParsersFuzzer_seed_corpus.zip
find ${SRC}/project-parent/tika -name "*.gif" -print0 | xargs -0 zip -u ${SRC}/seeds/ImageParsersFuzzer_seed_corpus.zip
find ${SRC}/project-parent/tika -name "*.heic" -print0 | xargs -0 zip -u ${SRC}/seeds/ImageParsersFuzzer_seed_corpus.zip
find ${SRC}/project-parent/tika -name "*.icns" -print0 | xargs -0 zip -u ${SRC}/seeds/ImageParsersFuzzer_seed_corpus.zip
find ${SRC}/project-parent/tika -name "*.jp2" -print0 | xargs -0 zip -u ${SRC}/seeds/ImageParsersFuzzer_seed_corpus.zip
find ${SRC}/project-parent/tika -name "*.jb2" -print0 | xargs -0 zip -u ${SRC}/seeds/ImageParsersFuzzer_seed_corpus.zip
find ${SRC}/project-parent/tika -name "*.jpg" -print0 | xargs -0 zip -u ${SRC}/seeds/ImageParsersFuzzer_seed_corpus.zip
find ${SRC}/project-parent/tika -name "*.jxl" -print0 | xargs -0 zip -u ${SRC}/seeds/ImageParsersFuzzer_seed_corpus.zip
find ${SRC}/project-parent/tika -name "*.png" -print0 | xargs -0 zip -u ${SRC}/seeds/ImageParsersFuzzer_seed_corpus.zip
find ${SRC}/project-parent/tika -name "*.psd" -print0 | xargs -0 zip -u ${SRC}/seeds/ImageParsersFuzzer_seed_corpus.zip
find ${SRC}/project-parent/tika -name "*.tif" -print0 | xargs -0 zip -u ${SRC}/seeds/ImageParsersFuzzer_seed_corpus.zip
find ${SRC}/project-parent/tika -name "*.webp" -print0 | xargs -0 zip -u ${SRC}/seeds/ImageParsersFuzzer_seed_corpus.zip


find ${SRC}/project-parent/tika -name "*.mdb" -print0 | xargs -0 zip ${SRC}/seeds/JackcessParserFuzzer_seed_corpus.zip
find ${SRC}/project-parent/tika -name "*.accdb" -print0 | xargs -0 zip ${SRC}/seeds/JackcessParserFuzzer_seed_corpus.zip

find ${SRC}/project-parent/tika -name "*.one" -print0 | xargs -0 zip ${SRC}/seeds/OneNoteParserFuzzer_seed_corpus.zip

#we could get more seeds by cloning POI
find ${SRC}/project-parent/tika -name "*.msg" -print0 | xargs -0 zip -u ${SRC}/seeds/OfficeParserFuzzer_seed_corpus.zip
find ${SRC}/project-parent/tika -name "*.doc" -print0 | xargs -0 zip -u ${SRC}/seeds/OfficeParserFuzzer_seed_corpus.zip
find ${SRC}/project-parent/tika -name "*.ppt" -print0 | xargs -0 zip -u ${SRC}/seeds/OfficeParserFuzzer_seed_corpus.zip
find ${SRC}/project-parent/tika -name "*.xls" -print0 | xargs -0 zip -u ${SRC}/seeds/OfficeParserFuzzer_seed_corpus.zip

find ${SRC}/project-parent/tika -name "*.docm" -print0 | xargs -0 zip -u ${SRC}/seeds/OOXMLParserFuzzer_seed_corpus.zip
find ${SRC}/project-parent/tika -name "*.docx" -print0 | xargs -0 zip -u ${SRC}/seeds/OOXMLParserFuzzer_seed_corpus.zip
find ${SRC}/project-parent/tika -name "*.pptm" -print0 | xargs -0 zip -u ${SRC}/seeds/OOXMLParserFuzzer_seed_corpus.zip
find ${SRC}/project-parent/tika -name "*.pptx" -print0 | xargs -0 zip -u ${SRC}/seeds/OOXMLParserFuzzer_seed_corpus.zip
find ${SRC}/project-parent/tika -name "*.xlsm" -print0 | xargs -0 zip -u ${SRC}/seeds/OOXMLParserFuzzer_seed_corpus.zip
find ${SRC}/project-parent/tika -name "*.xlsx" -print0 | xargs -0 zip -u ${SRC}/seeds/OOXMLParserFuzzer_seed_corpus.zip

find ${SRC}/project-parent/tika -name "*.7z" -print0 | xargs -0 zip -u ${SRC}/seeds/PackageParserFuzzer_seed_corpus.zip
find ${SRC}/project-parent/tika -name "*.ar" -print0 | xargs -0 zip -u ${SRC}/seeds/PackageParserFuzzer_seed_corpus.zip
find ${SRC}/project-parent/tika -name "*.jar" -print0 | xargs -0 zip -u ${SRC}/seeds/PackageParserFuzzer_seed_corpus.zip
find ${SRC}/project-parent/tika -name "*.rar" -print0 | xargs -0 zip -u ${SRC}/seeds/PackageParserFuzzer_seed_corpus.zip
find ${SRC}/project-parent/tika -name "*.tar" -print0 | xargs -0 zip -u ${SRC}/seeds/PackageParserFuzzer_seed_corpus.zip
find ${SRC}/project-parent/tika -name "*.zip" -print0 | xargs -0 zip -u ${SRC}/seeds/PackageParserFuzzer_seed_corpus.zip
find ${SRC}/project-parent/tika -name "*.zlib" -print0 | xargs -0 zip -u ${SRC}/seeds/PackageParserFuzzer_seed_corpus.zip


#we could get more seeds by cloning PDFBox or...?
find ${SRC}/project-parent/tika -name "*.pdf" -print0 | xargs -0 zip ${SRC}/seeds/PDFParserFuzzer_seed_corpus.zip

find ${SRC}/project-parent/tika -name "*.eml" -print0 | xargs -0 zip ${SRC}/seeds/RFC822ParserFuzzer_seed_corpus.zip

find ${SRC}/project-parent/tika -name "*.rtf" -print0 | xargs -0 zip ${SRC}/seeds/RTFParserFuzzer_seed_corpus.zip

find ${SRC}/project-parent/tika -name "*.txt" -print0 | xargs -0 zip ${SRC}/seeds/TextAndCSVParserFuzzer_seed_corpus.zip
find ${SRC}/project-parent/tika -name "*.tsv" -print0 | xargs -0 zip -u ${SRC}/seeds/TextAndCSVParserFuzzer_seed_corpus.zip
find ${SRC}/project-parent/tika -name "*.csv" -print0 | xargs -0 zip -u ${SRC}/seeds/TextAndCSVParserFuzzer_seed_corpus.zip

find ${SRC}/project-parent/tika -name "*.xml" -print0 | xargs -0 zip ${SRC}/seeds/XMLReaderUtilsFuzzer_seed_corpus.zip

find ${SRC}/project-parent/tika -path '*/test-documents/*' -type f | xargs -n1 -d '\n' zip ${SRC}/seeds/AutoDetectParserFuzzer_seed_corpus.zip

cp ${SRC}/seeds/*_seed_corpus.zip ${OUT}/

