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

#include "OgreRoot.h"
#include "OgreStaticPluginLoader.h"

#include "OgreConfigFile.h"
#include "OgreException.h"
#include "OgreLogManager.h"
#include "OgreSTBICodec.h"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  static int initialized = 0;
  if (initialized == 0) {
    Ogre::LogManager *logMgr = new Ogre::LogManager();
    logMgr->createLog("OgreTest.log", true, false);
    logMgr->setMinLogLevel(Ogre::LML_TRIVIAL);
    initialized = 1;

    Ogre::Root root("");
    OgreBites::StaticPluginLoader mStaticPluginLoader;
    mStaticPluginLoader.load();
  }

  char filename[256];
  sprintf(filename, "/tmp/libfuzzer-%d.png", getpid());
  FILE *fp = fopen(filename, "wb");
  if (!fp) {
    return 0;
  }
  fwrite(data, size, 1, fp);
  fclose(fp);

  // Write an empty config file.
  char file_to_load[256];
  char file_to_save[256];
  sprintf(file_to_load, "/tmp/config-%d.cfg", getpid());
  sprintf(file_to_save, "/tmp/ftosave-%d.png", getpid());
  FILE *fp2 = fopen(file_to_load, "wb");
  if (!fp2) {
    return 0;
  }
  fwrite(" ", 1, 1, fp2);
  fclose(fp2);

  Ogre::ResourceGroupManager mgr;
  try {
    Ogre::STBIImageCodec::startup();
    Ogre::ConfigFile cf;
    cf.load(file_to_load);
    std::ifstream file1(filename, std::ios::in | std::ios::binary);
    Ogre::DataStreamPtr data1 =
        Ogre::DataStreamPtr(OGRE_NEW Ogre::FileStreamDataStream(&file1, false));
    Ogre::Image img;
    img.load(data1, "png");
    img.save(file_to_save);
  } catch (Ogre::ItemIdentityException) {
  } catch (Ogre::InternalErrorException) {
  }

  Ogre::STBIImageCodec::shutdown();
  unlink(filename);
  unlink(file_to_load);
  return 0;
}
