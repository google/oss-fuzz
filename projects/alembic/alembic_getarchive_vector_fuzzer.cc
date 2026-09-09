// Copyright 2026 Google LLC
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

#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <memory>
#include <vector>

#include "alembic/lib/Alembic/AbcCoreFactory/All.h"
#include "alembic/lib/Alembic/AbcCoreOgawa/All.h"
#include "alembic/lib/Alembic/AbcGeom/All.h"
#include "alembic/lib/Alembic/AbcMaterial/All.h"

#include "fuzzer_temp_file.h"

using Alembic::AbcCoreFactory::IFactory;
using Alembic::AbcGeom::IArchive;

void dumpArchiveInfo(const IArchive &archive) {
  if (!archive.valid()) {
    return;
  }
  
  // Basic archive validation - similar to existing fuzzer
  archive.getName();
  
  // Try to access top object to ensure archive is properly loaded
  const Alembic::AbcGeom::IObject top = archive.getTop();
  if (top.valid()) {
    top.getFullName();
    top.getNumChildren();
  }
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  // Need at least 4 bytes for a length prefix
  if (size < 4) {
    return 0;
  }
  
  std::vector<std::string> tempFiles;
  std::vector<std::unique_ptr<FuzzerTemporaryFile>> fileHandlers;
  
  size_t offset = 0;
  
  // Parse input format: [4-byte length][file data][4-byte length][file data]...
  while (offset + 4 <= size) {
    // Read 4-byte length prefix (little endian)
    uint32_t fileLen = 0;
    memcpy(&fileLen, data + offset, 4);
    offset += 4;
    
    // Prevent excessive memory allocation
    if (fileLen > 1024 * 1024) { // 1MB limit per file
      break;
    }
    
    // Check if we have enough data for this file
    if (offset + fileLen > size) {
      break;
    }
    
    // Create temporary file for this chunk
    auto tempFile = std::make_unique<FuzzerTemporaryFile>(data + offset, fileLen);
    tempFiles.push_back(tempFile->filename());
    fileHandlers.push_back(std::move(tempFile));
    
    offset += fileLen;
  }
  
  // Only proceed if we have at least one file
  if (!tempFiles.empty()) {
    try {
      IFactory factory;
      IArchive archive = factory.getArchive(tempFiles);
      
      // Process the archive if it's valid
      if (archive.valid()) {
        dumpArchiveInfo(archive);
      }
    } catch (...) {
      // Catch any exceptions to prevent fuzzer crashes
    }
  }
  
  return 0;
}
