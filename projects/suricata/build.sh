#!/bin/bash -eu
# Copyright 2019 Google Inc.
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

# build dependencies statically
(
tar -xvzf pcre2-10.39.tar.gz
cd pcre2-10.39
./configure --disable-shared
make -j$(nproc) clean
make -j$(nproc) all
make -j$(nproc) install
)

tar -xvzf lz4-1.9.2.tar.gz
cd lz4-1.9.2
make liblz4.a
cp lib/liblz4.a /usr/local/lib/
cp lib/lz4*.h /usr/local/include/
cd ..

tar -xvzf jansson-2.12.tar.gz
cd jansson-2.12
./configure --disable-shared
make -j$(nproc)
make install
cd ..

tar -xvzf libpcap-1.9.1.tar.gz
cd libpcap-1.9.1
./configure --disable-shared
make -j$(nproc)
make install
cd ..

cd fuzzpcap
mkdir build
cd build
cmake ..
make install
cd ../..

cd libyaml
./bootstrap
./configure --disable-shared
make -j$(nproc)
make install
cd ..

export CARGO_BUILD_TARGET="x86_64-unknown-linux-gnu"
# cf https://github.com/google/sanitizers/issues/1389
export MSAN_OPTIONS=strict_memcmp=false

#we did not put libhtp there before so that cifuzz does not remove it
mv libhtp suricata/
# build project
cd suricata
sh autogen.sh
#run configure with right options
if [ "$SANITIZER" = "address" ]
then
    export RUSTFLAGS="$RUSTFLAGS -Cpasses=sancov-module -Cllvm-args=-sanitizer-coverage-level=4 -Cllvm-args=-sanitizer-coverage-trace-compares -Cllvm-args=-sanitizer-coverage-inline-8bit-counters -Cllvm-args=-sanitizer-coverage-pc-table -Clink-dead-code -Cllvm-args=-sanitizer-coverage-stack-depth -Ccodegen-units=1"
    export RUSTFLAGS="$RUSTFLAGS -Cdebug-assertions=yes"
fi
./src/tests/fuzz/oss-fuzz-configure.sh
make -j$(nproc)

./src/suricata --list-app-layer-protos | tail -n +2 | while read i; do cp src/fuzz_applayerparserparse $OUT/fuzz_applayerparserparse_$i; done

cp src/fuzz_* $OUT/

# dictionaries
./src/suricata --list-keywords | grep "\- " | sed 's/- //' | awk '{print "\""$0"\""}' > $OUT/fuzz_siginit.dict

echo \"SMB\" > $OUT/fuzz_applayerparserparse_smb.dict

echo "\"FPC0\"" > $OUT/fuzz_sigpcap_aware.dict
echo "\"FPC0\"" > $OUT/fuzz_predefpcap_aware.dict

git grep tag rust | grep '"' | cut -d '"' -f2 | sort | uniq | awk 'length($0) > 2' | awk '{print "\""$0"\""}' > generic.dict
cat generic.dict >> $OUT/fuzz_siginit.dict
cat generic.dict >> $OUT/fuzz_applayerparserparse.dict
cat generic.dict >> $OUT/fuzz_sigpcap.dict
cat generic.dict >> $OUT/fuzz_sigpcap_aware.dict

# build corpuses
# default configuration file
zip -r $OUT/fuzz_confyamlloadstring_seed_corpus.zip suricata.yaml
# rebuilds rules corpus with only one rule by file
unzip ../emerging.rules.zip
cd rules
cat *.rules > $OUT/fuzz.rules
i=0
mkdir corpus
# quiet output for commands
set +x
cat *.rules | while read l; do echo $l > corpus/$i.rule; i=$((i+1)); done
set -x
zip -q -r $OUT/fuzz_siginit_seed_corpus.zip corpus
cd ../../suricata-verify

# corpus with single files
find . -name "*.pcap" | xargs zip -r $OUT/fuzz_decodepcapfile_seed_corpus.zip
find . -name "*.yaml" | xargs zip -r $OUT/fuzz_confyamlloadstring_seed_corpus.zip
find . -name "*.rules" | xargs zip -r $OUT/fuzz_siginit_seed_corpus.zip

# corpus using both rule and pcap as in suricata-verify
cd tests
i=0
mkdir corpus
set +x
ls | grep -v corpus | while read t; do
cat $t/*.rules > corpus/$i || true; echo -ne '\0' >> corpus/$i; cat $t/*.pcap >> corpus/$i || true; i=$((i+1));
done
set -x
zip -q -r $OUT/fuzz_sigpcap_seed_corpus.zip corpus
rm -Rf corpus
mkdir corpus
set +x
ls | grep -v corpus | while read t; do
grep -v "#" $t/*.rules | head -1 | cut -d "(" -f2 | cut -d ")" -f1 > corpus/$i || true; echo -ne '\0' >> corpus/$i; fpc_bin $t/*.pcap >> corpus/$i || rm corpus/$i; i=$((i+1));
echo -ne '\0' >> corpus/$i; python3 $SRC/fuzzpcap/tcptofpc.py $t/*.pcap >> corpus/$i || rm corpus/$i; i=$((i+1));
done
set -x
zip -q -r $OUT/fuzz_sigpcap_aware_seed_corpus.zip corpus
rm -Rf corpus
mkdir corpus
set +x
ls | grep -v corpus | while read t; do
fpc_bin $t/*.pcap >> corpus/$i || rm corpus/$i; i=$((i+1));
python3 $SRC/fuzzpcap/tcptofpc.py $t/*.pcap >> corpus/$i || rm corpus/$i; i=$((i+1));
done
set -x
zip -q -r $OUT/fuzz_predefpcap_aware_seed_corpus.zip corpus
