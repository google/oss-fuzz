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

build_dir=$WORK/build-$SANITIZER
install_dir=$WORK/install-$SANITIZER

mkdir -p $build_dir
pushd $build_dir
cmake -D CMAKE_BUILD_TYPE=Release -D CMAKE_INSTALL_PREFIX=$install_dir \
  -DBUILD_SHARED_LIBS=OFF -DOPENCV_GENERATE_PKGCONFIG=ON \
  -DOPENCV_GENERATE_PKGCONFIG=ON -DOPENCV_FORCE_3RDPARTY_BUILD=ON \
  -DBUILD_TESTS=OFF -DBUILD_PERF_TESTS=OFF -DBUILD_opencv_apps=OFF \
  $SRC/opencv
make -j$(nproc)
make install
popd

pushd $SRC
for fuzzer in core_fuzzer filestorage_read_file_fuzzer \
   filestorage_read_filename_fuzzer filestorage_read_string_fuzzer \
   generateusergallerycollage_fuzzer imdecode_fuzzer imencode_fuzzer \
   imread_fuzzer readnetfromtensorflow_fuzzer; do
$CXX $CXXFLAGS $LIB_FUZZING_ENGINE $fuzzer.cc -std=c++11 \
-I$install_dir/include/opencv4 -L$install_dir/lib \
-L$install_dir/lib/opencv4/3rdparty \
-lopencv_dnn -lopencv_objdetect -lopencv_photo -lopencv_ml -lopencv_gapi \
-lopencv_stitching -lopencv_video -lopencv_calib3d -lopencv_features2d \
-lopencv_highgui -lopencv_videoio -lopencv_imgcodecs -lopencv_imgproc \
-lopencv_flann -lopencv_core -llibjpeg-turbo -llibwebp -llibpng -llibtiff \
-llibopenjp2 -lIlmImf -llibprotobuf -lquirc -lzlib -littnotify -lippiw \
-lippicv -lade -ldl -lm -lpthread -lrt \
-o $OUT/$fuzzer
done
popd
