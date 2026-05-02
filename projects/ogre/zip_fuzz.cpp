/* Copyright 2026 Google LLC
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

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "OgreArchive.h"
#include "OgreArchiveManager.h"
#include "OgreLogManager.h"
#include "OgreZip.h"
#include "OgreResourceGroupManager.h"

static bool g_initialized = false;
static Ogre::EmbeddedZipArchiveFactory* g_zipFactory = nullptr;

static void global_init() {
  if (g_initialized)
    return;

  auto *logMgr = new Ogre::LogManager();
  logMgr->createLog("fuzz_zip.log", true, false, true);
  logMgr->setMinLogLevel(Ogre::LML_CRITICAL);

  new Ogre::ResourceGroupManager();
  new Ogre::ArchiveManager();
  
  g_zipFactory = new Ogre::EmbeddedZipArchiveFactory();
  Ogre::ArchiveManager::getSingleton().addArchiveFactory(g_zipFactory);

  g_initialized = true;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  if (size < 1)
    return 0;

  global_init();

  Ogre::String name = "fuzz.zip";
  g_zipFactory->addEmbbeddedFile(name, data, size, nullptr);

  Ogre::Archive *arch = g_zipFactory->createInstance(name, true);
  if (arch) {
    try {
      arch->load();
      
      // List files
      Ogre::StringVectorPtr files = arch->list();
      
      // Try to open first few files
      int count = 0;
      for (auto &f : *files) {
        if (count++ > 10) break;
        try {
          Ogre::DataStreamPtr stream = arch->open(f);
          if (stream) {
            // Read some data
            char buf[1024];
            stream->read(buf, std::min((size_t)1024, (size_t)stream->size()));
          }
        } catch (...) {}
      }
      
      arch->unload();
    } catch (...) {}
    g_zipFactory->destroyInstance(arch);
  }

  return 0;
}
