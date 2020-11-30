#!/bin/bash -eu
# Copyright 2020 Google LLC
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
cd Pillow

make || true
$CXX -pthread -shared $CXXFLAGS $LIB_FUZZING_ENGINE build/temp.linux-x86_64-3.8/src/_imaging.o build/temp.linux-x86_64-3.8/src/decode.o build/temp.linux-x86_64-3.8/src/encode.o build/temp.linux-x86_64-3.8/src/map.o build/temp.linux-x86_64-3.8/src/display.o build/temp.linux-x86_64-3.8/src/outline.o build/temp.linux-x86_64-3.8/src/path.o build/temp.linux-x86_64-3.8/src/libImaging/Access.o build/temp.linux-x86_64-3.8/src/libImaging/AlphaComposite.o build/temp.linux-x86_64-3.8/src/libImaging/Resample.o build/temp.linux-x86_64-3.8/src/libImaging/Reduce.o build/temp.linux-x86_64-3.8/src/libImaging/Bands.o build/temp.linux-x86_64-3.8/src/libImaging/BcnDecode.o build/temp.linux-x86_64-3.8/src/libImaging/BitDecode.o build/temp.linux-x86_64-3.8/src/libImaging/Blend.o build/temp.linux-x86_64-3.8/src/libImaging/Chops.o build/temp.linux-x86_64-3.8/src/libImaging/ColorLUT.o build/temp.linux-x86_64-3.8/src/libImaging/Convert.o build/temp.linux-x86_64-3.8/src/libImaging/ConvertYCbCr.o build/temp.linux-x86_64-3.8/src/libImaging/Copy.o build/temp.linux-x86_64-3.8/src/libImaging/Crop.o build/temp.linux-x86_64-3.8/src/libImaging/Dib.o build/temp.linux-x86_64-3.8/src/libImaging/Draw.o build/temp.linux-x86_64-3.8/src/libImaging/Effects.o build/temp.linux-x86_64-3.8/src/libImaging/EpsEncode.o build/temp.linux-x86_64-3.8/src/libImaging/File.o build/temp.linux-x86_64-3.8/src/libImaging/Fill.o build/temp.linux-x86_64-3.8/src/libImaging/Filter.o build/temp.linux-x86_64-3.8/src/libImaging/FliDecode.o build/temp.linux-x86_64-3.8/src/libImaging/Geometry.o build/temp.linux-x86_64-3.8/src/libImaging/GetBBox.o build/temp.linux-x86_64-3.8/src/libImaging/GifDecode.o build/temp.linux-x86_64-3.8/src/libImaging/GifEncode.o build/temp.linux-x86_64-3.8/src/libImaging/HexDecode.o build/temp.linux-x86_64-3.8/src/libImaging/Histo.o build/temp.linux-x86_64-3.8/src/libImaging/JpegDecode.o build/temp.linux-x86_64-3.8/src/libImaging/JpegEncode.o build/temp.linux-x86_64-3.8/src/libImaging/Matrix.o build/temp.linux-x86_64-3.8/src/libImaging/ModeFilter.o build/temp.linux-x86_64-3.8/src/libImaging/Negative.o build/temp.linux-x86_64-3.8/src/libImaging/Offset.o build/temp.linux-x86_64-3.8/src/libImaging/Pack.o build/temp.linux-x86_64-3.8/src/libImaging/PackDecode.o build/temp.linux-x86_64-3.8/src/libImaging/Palette.o build/temp.linux-x86_64-3.8/src/libImaging/Paste.o build/temp.linux-x86_64-3.8/src/libImaging/Quant.o build/temp.linux-x86_64-3.8/src/libImaging/QuantOctree.o build/temp.linux-x86_64-3.8/src/libImaging/QuantHash.o build/temp.linux-x86_64-3.8/src/libImaging/QuantHeap.o build/temp.linux-x86_64-3.8/src/libImaging/PcdDecode.o build/temp.linux-x86_64-3.8/src/libImaging/PcxDecode.o build/temp.linux-x86_64-3.8/src/libImaging/PcxEncode.o build/temp.linux-x86_64-3.8/src/libImaging/Point.o build/temp.linux-x86_64-3.8/src/libImaging/RankFilter.o build/temp.linux-x86_64-3.8/src/libImaging/RawDecode.o build/temp.linux-x86_64-3.8/src/libImaging/RawEncode.o build/temp.linux-x86_64-3.8/src/libImaging/Storage.o build/temp.linux-x86_64-3.8/src/libImaging/SgiRleDecode.o build/temp.linux-x86_64-3.8/src/libImaging/SunRleDecode.o build/temp.linux-x86_64-3.8/src/libImaging/TgaRleDecode.o build/temp.linux-x86_64-3.8/src/libImaging/TgaRleEncode.o build/temp.linux-x86_64-3.8/src/libImaging/Unpack.o build/temp.linux-x86_64-3.8/src/libImaging/UnpackYCC.o build/temp.linux-x86_64-3.8/src/libImaging/UnsharpMask.o build/temp.linux-x86_64-3.8/src/libImaging/XbmDecode.o build/temp.linux-x86_64-3.8/src/libImaging/XbmEncode.o build/temp.linux-x86_64-3.8/src/libImaging/ZipDecode.o build/temp.linux-x86_64-3.8/src/libImaging/ZipEncode.o build/temp.linux-x86_64-3.8/src/libImaging/TiffDecode.o build/temp.linux-x86_64-3.8/src/libImaging/Jpeg2KDecode.o build/temp.linux-x86_64-3.8/src/libImaging/Jpeg2KEncode.o build/temp.linux-x86_64-3.8/src/libImaging/BoxBlur.o build/temp.linux-x86_64-3.8/src/libImaging/QuantPngQuant.o build/temp.linux-x86_64-3.8/src/libImaging/codec_fd.o -L/usr/local/lib -L/lib/x86_64-linux-gnu -L/usr/lib/x86_64-linux-gnu -L/usr/lib/x86_64-linux-gnu/libfakeroot -L/usr/lib -L/lib -L/usr/local/lib -ljpeg -lz -o /src/Pillow/src/PIL/_imaging.cpython-38-x86_64-linux-gnu.so -stdlib=libc++

# Build fuzzers in $OUT.
for fuzzer in $(find $SRC -name 'fuzz_*.py'); do
  fuzzer_basename=$(basename -s .py $fuzzer)
  fuzzer_package=${fuzzer_basename}.pkg
  pyinstaller --distpath $OUT --onefile --name $fuzzer_package $fuzzer

  # Create execution wrapper.
  echo "#/bin/sh
# LLVMFuzzerTestOneInput for fuzzer detection.
LD_PRELOAD=\$(dirname "\$0")/libclang_rt.asan-x86_64.so \$(dirname "\$0")/$fuzzer_package \$@" > $OUT/$fuzzer_basename
  chmod u+x $OUT/$fuzzer_basename
done


