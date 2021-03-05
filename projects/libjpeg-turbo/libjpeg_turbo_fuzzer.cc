/*
# Copyright 2016 Google Inc.
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
*/

#include <stdint.h>
#include <stdlib.h>

#include <memory>

#include <turbojpeg.h>


extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    tjhandle jpegDecompressor = tjInitDecompress();

    int width, height, subsamp, colorspace;
    int res = tjDecompressHeader3(
        jpegDecompressor, data, size, &width, &height, &subsamp, &colorspace);

    // Bail out if decompressing the headers failed, the width or height is 0,
    // or the image is too large (avoids slowing down too much). Cast to size_t to
    // avoid overflows on the multiplication
    if (res != 0 || width == 0 || height == 0 || ((size_t)width * height > (1024 * 1024))) {
        tjDestroy(jpegDecompressor);
        return 0;
    }

    const int buffer_size = width * height * 3;
    std::unique_ptr<unsigned char[]> buf(new unsigned char[buffer_size]);
    tjDecompress2(
        jpegDecompressor, data, size, buf.get(), width, 0, height, TJPF_RGB, 0);

    // For memory sanitizer, test each output byte
    const unsigned char* raw_buf = buf.get();
    int count = 0;
    for( int i = 0; i < buffer_size; i++ )
    {
        if (raw_buf[i])
        {
            count ++;
        }
    }
    if (count == buffer_size)
    {
        // Do something with side effect, so that all the above tests don't
        // get removed by the optimizer.
        free(malloc(1));
    }

    tjDestroy(jpegDecompressor);

    return 0;
}
