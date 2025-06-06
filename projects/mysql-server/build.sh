
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

cd mysql-server
mkdir build
cd build
# maybe we need to add WITH_LSAN
export MY_SANITIZER="-DWITH_ASAN=ON"
if [[ $SANITIZER = *undefined* ]]; then
    export MY_SANITIZER="-DWITH_UBSAN=ON"
fi
# not handling yet WITH_MSAN nor WITH_TSAN
cmake .. -DBUILD_SHARED_LIBS=OFF -Dprotobuf_BUILD_SHARED_LIBS=OFF -DWITH_SSL=system -DCMAKE_INSTALL_PREFIX=$OUT/mysql -DWITH_LD=lld $MY_SANITIZER -DCMAKE_VERBOSE_MAKEFILE=ON
make -j$(nproc)
mkdir -p $OUT/lib/
cp library_output_directory/libmysql*.so.* $OUT/lib/
(
cd runtime_output_directory/
ls *fuzz* | while read i; do
    cp $i $OUT/
    chrpath -r '$ORIGIN/lib' $OUT/$i
done
)

#TODO merge custom targets upstream
#cp ../fuzz/fuzz*.options $OUT/
#cp ../fuzz/fuzz*.dict $OUT/
#cp ../fuzz/init*.sql $OUT/

#rm -Rf $OUT/mysql/data
#$OUT/mysql/bin/mysqld --user=root --initialize-insecure --log-error-verbosity=5 --skip-ssl --datadir=$OUT/mysql/data --basedir=$OUT/mysql/
