#!/bin/bash -eu
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

# Copy seed corpus and dictionary.
mv $SRC/{*.zip,*.dict} $OUT


export MODDABLE=$PWD

FUZZ_TARGETS=(
  xst
  xst_jsonparse
)

REALBIN_PATH=$OUT

# build main target
cd "$MODDABLE/xs/makefiles/lin"
FUZZING=1 OSSFUZZ=1 FUZZ_METER=10240000 make debug

cd "$MODDABLE"
cp ./build/bin/lin/debug/xst $REALBIN_PATH/xst
cp $SRC/xst.options $OUT/

# build jsonparse target
cd "$MODDABLE/xs/makefiles/lin"
make -f xst.mk clean
FUZZING=1 OSSFUZZ=1 OSSFUZZ_JSONPARSE=1 FUZZ_METER=10240000 make debug

cd "$MODDABLE"
cp ./build/bin/lin/debug/xst $REALBIN_PATH/xst_jsonparse

cp $SRC/xst.options $OUT/xst_jsonparse.options
