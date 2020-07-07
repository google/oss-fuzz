// Copyright 2020 Google LLC
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

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <ImfArray.h>
#include <ImfInputPart.h>
#include <ImfMultiPartInputFile.h>
#include <ImfRgbaFile.h>

using namespace OPENEXR_IMF_INTERNAL_NAMESPACE;
using IMATH_NAMESPACE::Box2i;

namespace {

static void readSingle(const char fileName[]) {
  RgbaInputFile *in = NULL;
  try {
    in = new RgbaInputFile(fileName);
  } catch (...) {
    return;
  }

  try {
    const Box2i &dw = in->dataWindow();

    int w = dw.max.x - dw.min.x + 1;
    int dx = dw.min.x;

    if (w > (1 << 24)) return;

    Array<Rgba> pixels(w);
    in->setFrameBuffer(&pixels[-dx], 1, 0);

    for (int y = dw.min.y; y <= dw.max.y; ++y) in->readPixels(y);
  } catch (...) {
  }

  delete in;
}

static void readMulti(const char fileName[]) {
  MultiPartInputFile *file;
  try {
    file = new MultiPartInputFile(fileName);
  } catch (...) {
    return;
  }

  for (int p = 0; p < file->parts(); p++) {
    InputPart *in;
    try {
      in = new InputPart(*file, p);
    } catch (...) {
      continue;
    }

    try {
      const Box2i &dw = in->header().dataWindow();

      int w = dw.max.x - dw.min.x + 1;
      int dx = dw.min.x;

      if (w > (1 << 24)) return;

      Array<Rgba> pixels(w);
      FrameBuffer i;
      i.insert("R", Slice(HALF, (char *)&(pixels[-dx].r), sizeof(Rgba), 0));
      i.insert("G", Slice(HALF, (char *)&(pixels[-dx].g), sizeof(Rgba), 0));
      i.insert("B", Slice(HALF, (char *)&(pixels[-dx].b), sizeof(Rgba), 0));
      i.insert("A", Slice(HALF, (char *)&(pixels[-dx].a), sizeof(Rgba), 0));

      in->setFrameBuffer(i);
      for (int y = dw.min.y; y <= dw.max.y; ++y) in->readPixels(y);
    } catch (...) {
    }

    delete in;
  }

  delete file;
}

}  // namespace

// from cl/164883104
static char *buf_to_file(const char *buf, size_t size) {
  char *name = strdup("/dev/shm/fuzz-XXXXXX");
  int fd = mkstemp(name);
  if (fd < 0) {
    perror("open");
    exit(1);
  }
  size_t pos = 0;
  while (pos < size) {
    int nbytes = write(fd, &buf[pos], size - pos);
    if (nbytes <= 0) {
      perror("write");
      exit(1);
    }
    pos += nbytes;
  }
  if (close(fd) != 0) {
    perror("close");
    exit(1);
  }
  return name;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  char *file = buf_to_file((const char *)data, size);
  readSingle(file);
  readMulti(file);
  unlink(file);
  free(file);
  return 0;
}
