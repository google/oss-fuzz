#!/bin/bash -eu
#
# Copyright 2023 Google LLC
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

FILAMENT=$SRC/filament

# Build meshoptimizer object files
for src in vertexcodec.cpp indexcodec.cpp vertexfilter.cpp; do
    $CXX $CXXFLAGS -c $FILAMENT/third_party/meshoptimizer/src/$src \
        -o $WORK/$(basename $src .cpp).o
done

# Build the fuzz target
# cgltf is header-only (CGLTF_IMPLEMENTATION defined in the fuzzer source)
$CXX $CXXFLAGS $LIB_FUZZING_ENGINE $SRC/fuzz_gltf_meshopt.cpp \
    $WORK/vertexcodec.o $WORK/indexcodec.o $WORK/vertexfilter.o \
    -I$FILAMENT/third_party/cgltf \
    -I$FILAMENT/third_party/meshoptimizer/src \
    -o $OUT/fuzz_gltf_meshopt

# Seed corpus with minimal GLB and a GLB containing meshopt extension
mkdir -p $WORK/corpus

python3 -c "
import struct, json

def make_glb(gltf, bin_data=b''):
    jb = json.dumps(gltf, separators=(',',':')).encode()
    jb += b' ' * ((4 - len(jb) % 4) % 4)
    jc = struct.pack('<II', len(jb), 0x4E4F534A) + jb
    bc = b''
    if bin_data:
        bp = (4 - len(bin_data) % 4) % 4
        bd = bin_data + b'\x00' * bp
        bc = struct.pack('<II', len(bd), 0x004E4942) + bd
    t = 12 + len(jc) + len(bc)
    return struct.pack('<III', 0x46546C67, 2, t) + jc + bc

# 1. Minimal valid GLB
g = {'asset':{'version':'2.0'},'scene':0,'scenes':[{'nodes':[]}]}
open('\$WORK/corpus/minimal.glb','wb').write(make_glb(g))

# 2. GLB with EXT_meshopt_compression (exercises the decode path)
fake_comp = bytes([0xa0]) + b'\x00' * 63
bin_data = fake_comp
g = {
    'asset':{'version':'2.0'},
    'scene':0,'scenes':[{'nodes':[0]}],'nodes':[{'mesh':0}],
    'meshes':[{'primitives':[{'attributes':{'POSITION':0}}]}],
    'accessors':[
        {'bufferView':0,'componentType':5126,'count':1,'type':'VEC3',
         'max':[1,1,1],'min':[0,0,0]},
    ],
    'bufferViews':[
        {'buffer':0,'byteOffset':0,'byteLength':12,'byteStride':12,
         'extensions':{'EXT_meshopt_compression':{
             'buffer':0,'byteOffset':0,'byteLength':len(fake_comp),
             'byteStride':12,'count':1,'mode':'ATTRIBUTES'}}},
    ],
    'buffers':[{'byteLength':len(bin_data)}],
    'extensionsUsed':['EXT_meshopt_compression'],
}
open('\$WORK/corpus/meshopt.glb','wb').write(make_glb(g, bin_data))
"

zip -j $OUT/fuzz_gltf_meshopt_seed_corpus.zip $WORK/corpus/*
