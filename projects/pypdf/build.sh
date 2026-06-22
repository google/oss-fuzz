#!/bin/bash -eu
pip3 install .
# Build a high-quality seed corpus to maximize code coverage
mkdir -p corpus_temp
cd corpus_temp
# Download diverse PDFs (Encrypted, Forms, Images, Text)
curl -sLO https://raw.githubusercontent.com/mozilla/pdf.js/master/test/pdfs/tracemonkey.pdf
curl -sLO https://raw.githubusercontent.com/mozilla/pdf.js/master/test/pdfs/bug1056586.pdf
curl -sLO https://raw.githubusercontent.com/mozilla/pdf.js/master/test/pdfs/xfa_form_calc_check.pdf

zip -q $OUT/pypdf_fuzzer_seed_corpus.zip *.pdf
cd ..
rm -rf corpus_temp
for fuzzer in $(find $SRC -name '*_fuzzer.py'); do
  compile_python_fuzzer $fuzzer
done