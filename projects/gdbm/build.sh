#!/bin/bash -eu
# Copyright 2021 Google Inc.
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

# Bootstrap and configure project
./bootstrap --no-po
./configure --disable-shared --enable-debug --disable-nls
# Build project
make -j$(nproc) all
# Build fuzzer
cd fuzz
$CC $CFLAGS -c -I.. -I../src -ogdbm_fuzzer.o gdbm_fuzzer.c
$CXX $CFLAGS -ogdbm_fuzzer gdbm_fuzzer.o ../src/libgdbmapp.a ../src/.libs/libgdbm.a $LIB_FUZZING_ENGINE

cp gdbm_fuzzer $OUT

cat > $OUT/gdbm_fuzzer.rc <<EOF
set errorexit
open
set noerrorexit
set errormask
avail 
cache 
count 
dir 
header 
current 
first 
next 
status 
set coalesce 
set centfree 
recover 
reorganize 
fetch 1 
delete 1 
store 1 1 
delete 1 
bucket 1 
upgrade 
downgrade 
close 
quit
EOF

# Create seed
mkdir seed
cd seed
for format in standard numsync; do
    ../../src/gdbmtool << EOF
set format=$format
open empty_$format
close

open one_$format
store key1 value1
close

set blocksize=512
open empty_b512_$format
close

set cachesize=512
open empty_b512_c512_$format
close

open one_b512_c512_$format
store key1 value1
close

open ten_b512_c512_$format
store key1 value1
store key2 value2
store key3 value3
store key4 value4
store key5 value5
store key6 value6
store key7 value7
store key8 value8
store key9 value9
store key10 value10

open nine_b512_c512_$format
store key1 value1
store key2 value2
store key3 value3
store key4 value4
store key5 value5
store key6 value6
store key7 value7
store key8 value8
store key9 value9
store key10 value10
delete key1
close

open one_b512_c512_ku_cs_$format
define key { uint k }
define content { string s }
store 1 value1
close

open one_b512_c512_ku_cu_$format
define key { uint k }
define content { uint v }
store 1 1
define key { string k }
store key1 1
define key { uint k }
define content { uint v[2] }
store 1 { { 1 , 2 } }
list
close

open one_b512_c512_ku_cusz_$format
define key { uint k }
define content { uint v, stringz s }
store 1 { 1 , value1 }
list
close
quit
EOF
done

cd ..
zip -rj "$OUT/gdbm_fuzzer_seed_corpus.zip" seed/


	    
