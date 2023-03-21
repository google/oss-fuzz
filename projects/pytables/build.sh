#!/bin/bash -eu

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
##########################################################################

if [ $SANITIZER == "coverage" ]; then
  unset CFLAGS
  unset CXXFLAGS
fi

# Build supported version of HDF5 with relevant sanitizers.
cd $SRC/
wget https://support.hdfgroup.org/ftp/HDF5/releases/hdf5-1.10/hdf5-1.10.5/src/hdf5-1.10.5.tar.gz
tar -xf hdf5-1.10.5.tar.gz
cd hdf5-1.10.5/                                                  
./configure --prefix=/usr/
make -j4                                                  
make install

cd $SRC/pytables

python3 ./setup.py install
python3 -m pip install .

for fuzzer in $(find $SRC -name 'fuzz_*.py'); do
  compile_python_fuzzer $fuzzer --add-data "/usr/local/lib64/libblosc2.so.2.7.1:." --add-data "/usr/local/lib64/libblosc2.so.2:." --add-data "/usr/local/lib64/libblosc2.so:."
done

# Create corpus
mkdir $SRC/corpus
find ./tables/tests -name "*.h5" -exec cp {} $SRC/corpus/ \;
zip -rj $OUT/fuzz_1_seed_corpus.zip $SRC/corpus/*
