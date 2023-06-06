/* Copyright 2023 Google LLC
Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at
      http://www.apache.org/licenses/LICENSE-2.0
Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

/*
 * The main idea behind this fuzzer is the generate arbitrary stack traces
 * by way of recursive funcitons, and then using various calls to libunwind
 * apis arbitrarily.
 */
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include <iostream>
#include <string>

#include "OgreException.h"
#include "OgreFileSystem.h"
#include "OgreStreamSerialiser.h"
#include "OgreVector.h"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  char filename[256];
  sprintf(filename, "/tmp/libfuzzer.%d", getpid());

  FILE *fp = fopen(filename, "wb");
  if (!fp) {
    return 0;
  }
  fwrite(data, size, 1, fp);
  fclose(fp);

  Ogre::String fileName = filename;

  Ogre::FileSystemArchiveFactory factory;
  Ogre::Archive *arch = factory.createInstance("/tmp/", false);
  arch->load();

  Ogre::DataStreamPtr stream = arch->open(fileName);
  Ogre::StreamSerialiser serialiser(stream);
  try {
    const Ogre::StreamSerialiser::Chunk *c = serialiser.readChunkBegin();

    Ogre::Vector3 dest;
    serialiser.read(&dest, 1);
  } catch (Ogre::InvalidStateException) {
  }
  factory.destroyInstance(arch);
  unlink(filename);

  return 0;
}
