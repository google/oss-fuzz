
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
git apply ../fix.diff
mkdir build
cd build
if [[ $SANITIZER = *undefined* ]]; then
    cmake .. -Dprotobuf_BUILD_SHARED_LIBS=OFF -DDOWNLOAD_BOOST=1 -DWITH_BOOST=. -DWITH_SSL=system -DFUZZING=1 -DCMAKE_INSTALL_PREFIX=$OUT/mysql -DWITH_UBSAN=1
else
    cmake .. -Dprotobuf_BUILD_SHARED_LIBS=OFF -DDOWNLOAD_BOOST=1 -DWITH_BOOST=. -DWITH_SSL=system -DFUZZING=1 -DCMAKE_INSTALL_PREFIX=$OUT/mysql
fi
make -j$(nproc) install
mv $OUT/mysql/bin/fuzz* $OUT/
cp ../fuzz/fuzz*.options $OUT/
cp ../fuzz/fuzz*.dict $OUT/
cp ../fuzz/init*.sql $OUT/

rm -Rf $OUT/mysql/data
$OUT/mysql/bin/mysqld --user=root --initialize-insecure --log-error-verbosity=5 --skip-ssl --datadir=$OUT/mysql/data --basedir=$OUT/mysql/
