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

#include <turbojpeg.h>


extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    tjhandle jpegDecompressor = tjInitDecompress();

    int width, height, subsamp, colorspace;
    int res = tjDecompressHeader3(
        jpegDecompressor, data, size, &width, &height, &subsamp, &colorspace);

    if (res != 0 || width == 0 || height == 0) {
        tjDestroy(jpegDecompressor);
        return 0;
    }

    // TODO: this can't possibly be right?
    void *buf = malloc(width * height * 3);
    tjDecompress2(
        jpegDecompressor, data, size, reinterpret_cast<unsigned char *>(buf), width, 0, height, TJPF_RGB, 0);

    free(buf);
    tjDestroy(jpegDecompressor);

    return 0;
}
