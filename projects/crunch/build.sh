#!/bin/bash -eu
# Copyright 2021 Google LLC
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

cd crnlib
sed -i 's/c1,c2,len, get8(s)/(stbi_uc)c1,(stbi_uc)c2,(stbi_uc)len, (stbi_uc)get8(s)/g' ./crn_stb_image.cpp
sed -i 's/\"\\0\\0\\04\\02\\06\"\[num_chans\]/(mz_uint8)(\"\\0\\0\\04\\02\\06\"\[num_chans\])/g' ./crn_miniz.cpp
make V=1
cp crunch_fuzz $OUT/crunch_fuzz
