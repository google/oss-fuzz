// Copyright 2020 Google Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#include "include/flac_parser.h"
#include <assert.h>
#include <string>

namespace {

  class FuzzDataSource : public DataSource {
    const uint8_t *data_;
    size_t size_;

   public:
    FuzzDataSource(const uint8_t *data, size_t size) {
      data_ = data;
      size_ = size;
    }

    ssize_t readAt(off64_t offset, void *const data, size_t size) {
      if (offset > size_)
        return -1;
      size_t remaining = size_ - offset;
      if (remaining < size)
        size = remaining;
      memcpy(data, data_ + offset, size);
      return size;
    }
  };

}  // namespace

// Fuzz FLAC format and instrument the result as exoplayer JNI would:
// https://github.com/google/ExoPlayer/blob/release-v2/extensions/flac/src/main/jni/
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  FuzzDataSource source(data, size);
  FLACParser parser(&source);

  // Early parsing
  if (!parser.init() || !parser.decodeMetadata())
    return 0;

  auto streamInfo = parser.getStreamInfo();

  // Similar implementation than ExoPlayer
  int buffer_size = streamInfo.max_blocksize * streamInfo.channels * 2;
  assert(buffer_size >= 0);  // Not expected
  auto buffer = new uint8_t[buffer_size];
  int runs = 0;
  while (parser.readBuffer(buffer, buffer_size) >= buffer_size) {
    runs++;
    continue;
  }
  delete[] buffer;

  return 0;
}
