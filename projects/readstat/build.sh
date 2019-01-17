# Copyright 2019 Evan Miller
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

#!/bin/bash -eu

./autogen.sh
./configure --enable-static
make clean

make
make generate_corpus
./generate_corpus

zip $OUT/fuzz_format_dta_seed_corpus.zip corpus/dta*/test-case-*
zip $OUT/fuzz_format_por_seed_corpus.zip corpus/por/test-case-*
zip $OUT/fuzz_format_sav_seed_corpus.zip corpus/sav*/test-case-* corpus/zsav/test-case-*
zip $OUT/fuzz_format_sas7bcat_seed_corpus.zip corpus/sas7bcat/test-case-*
zip $OUT/fuzz_format_sas7bdat_seed_corpus.zip corpus/sas7bdat*/test-case-*
zip $OUT/fuzz_format_xport_seed_corpus.zip corpus/xpt*/test-case-*

READSTAT_FUZZERS="
    fuzz_format_dta \
    fuzz_format_por \
    fuzz_format_sav \
    fuzz_format_sas7bcat \
    fuzz_format_sas7bdat \
    fuzz_format_xport"

for fuzzer in $READSTAT_FUZZERS; do
    make ${fuzzer}
    cp ${fuzzer} $OUT/${fuzzer}
done
