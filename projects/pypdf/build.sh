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

pip install -v "pypdf[pdfminer,crypto]" Pillow pycryptodome atheris

compile_python_fuzzer \
  $SRC/pypdf_fuzzer.py \
  $OUT/pypdf_fuzzer \
  --dict=$SRC/pypdf.dict

cp $SRC/pypdf.dict $OUT/pypdf_fuzzer.dict

mkdir -p $OUT/pypdf_fuzzer_seed_corpus
CORPUS_DIR=$OUT/pypdf_fuzzer_seed_corpus

# 1. Minimal Valid PDF
python3 -c "
import sys
pdf_data = b'''%%PDF-1.4
1 0 obj << /Type /Catalog /Pages 2 0 R >> endobj
2 0 obj << /Type /Pages /Kids [3 0 R] /Count 1 >> endobj
3 0 obj << /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] >> endobj
xref 0 4
0000000000 65535 f 
0000000009 00000 n 
0000000058 00000 n 
0000000115 00000 n 
trailer << /Size 4 /Root 1 0 R >>
startxref 193
%%EOF'''
sys.stdout.buffer.write(pdf_data)
" > "$CORPUS_DIR/minimal.pdf"

# 2. PDF with FlateDecode Stream
python3 -c "
import sys
import zlib

content = b'BT /F1 12 Tf 100 700 Td (Hello World) Tj ET'
compressed = zlib.compress(content)

pdf_data = b'''%%PDF-1.4
1 0 obj << /Type /Catalog /Pages 2 0 R >> endobj
2 0 obj << /Type /Pages /Kids [3 0 R] /Count 1 >> endobj
3 0 obj << /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Contents 4 0 R /Resources << /Font << /F1 << /Type /Font /Subtype /Type1 /BaseFont /Helvetica >> >> >> >> endobj
4 0 obj << /Length ''' + str(len(compressed)).encode() + b''' /Filter /FlateDecode >>
stream
''' + compressed + b'''
endstream
endobj
xref 0 5
0000000000 65535 f 
0000000009 00000 n 
0000000058 00000 n 
0000000115 00000 n 
0000000245 00000 n 
0000000410 00000 n 
trailer << /Size 5 /Root 1 0 R >>
startxref 500
%%EOF'''
sys.stdout.buffer.write(pdf_data)
" > "$CORPUS_DIR/flate_stream.pdf"

# 3. PDF with Form Fields
python3 -c "
import sys
pdf_data = b'''%%PDF-1.4
1 0 obj << /Type /Catalog /Pages 2 0 R /AcroForm 4 0 R >> endobj
2 0 obj << /Type /Pages /Kids [3 0 R] /Count 1 >> endobj
3 0 obj << /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Annots [5 0 R] >> endobj
4 0 obj << /Fields [5 0 R] >> endobj
5 0 obj << /Type /Annot /Subtype /Widget /FT /Tx /T (Field1) >> endobj
xref 0 6
0000000000 65535 f 
0000000009 00000 n 
0000000076 00000 n 
0000000133 00000 n 
0000000238 00000 n 
0000000274 00000 n 
trailer << /Size 6 /Root 1 0 R >>
startxref 339
%%EOF'''
sys.stdout.buffer.write(pdf_data)
" > "$CORPUS_DIR/form.pdf"

cd $OUT
zip -q -r pypdf_fuzzer_seed_corpus.zip pypdf_fuzzer_seed_corpus/
cd $SRC

echo "=== Build Complete ==="