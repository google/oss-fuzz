#!/bin/bash -eu
# Copyright 2018 Google Inc.
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

./boot.sh && HAVE_UNWIND=no ./configure --enable-ndebug && make -j$(nproc) && make oss-fuzz-targets

cp $SRC/openvswitch/tests/oss-fuzz/config/*.options $OUT/
cp $SRC/openvswitch/tests/oss-fuzz/config/*.dict $OUT/
wget -O $OUT/json.dict https://raw.githubusercontent.com/rc0r/afl-fuzz/master/dictionaries/json.dict

for file in $SRC/openvswitch/tests/oss-fuzz/*_target;
do
       cp $file $OUT/
       name=$(basename $file)
       corp_name=$(basename $file _target)
       corp_dir=$SRC/ovs-fuzzing-corpus/${corp_name}_seed_corpus
       if [ -d ${corp_dir} ]; then
           zip -rq $OUT/${name}_seed_corpus ${corp_dir}
       fi
done
