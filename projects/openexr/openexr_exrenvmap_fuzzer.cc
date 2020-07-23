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

#include <makeCubeMap.h>
#include <makeLatLongMap.h>
#include <blurImage.h>
#include <EnvmapImage.h>
#include <ImfEnvmap.h>
#include <ImfHeader.h>

#include <iostream>
#include <exception>
#include <string>
#include <string.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

using namespace OPENEXR_IMF_NAMESPACE;
using namespace std;

static char *buf_to_file(const char *buf, size_t size) {
  char *name = strdup("/tmp/fuzz-XXXXXX");
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
  if (!file) return 0;

  Envmap overrideInputType = NUM_ENVMAPTYPES;
  LevelMode levelMode = ONE_LEVEL;
  LevelRoundingMode roundingMode = ROUND_DOWN;
  Compression compression = ZIP_COMPRESSION;
  int mapWidth = 256;
  int tileWidth = 64;
  int tileHeight = 64;
  int numSamples = 5;
  float filterRadius = 1;

  EnvmapImage image;
  Header header;
  RgbaChannels channels;

  try {
    readInputImage (file, 0, 0,
                    overrideInputType, false,
                    image, header, channels);

    makeCubeMap (image, header, channels,
                 "/dev/null",
                 tileWidth, tileHeight,
                 levelMode, roundingMode,
                 compression, mapWidth,
                 filterRadius, numSamples,
                 false);
  } catch (IEX_NAMESPACE::InputExc& e) {
    ;
  } catch (IEX_NAMESPACE::ArgExc& e) {
    ;
  }

  unlink(file);
  free(file);

  return 0;
}
