// Copyright 2025 Google LLC.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#include "indexer/frontend/common.h"

#include <cstdint>
#include <filesystem>  // NOLINT
#include <string>

#include "indexer/index/in_memory_index.h"
#include "indexer/index/types.h"
#include "absl/log/check.h"
#include "absl/strings/string_view.h"
#include "clang/Basic/SourceLocation.h"
#include "clang/Basic/SourceManager.h"
#include "llvm/Support/ErrorOr.h"

namespace oss_fuzz {
namespace indexer {

std::string ToNormalizedAbsolutePath(
    absl::string_view path, const clang::SourceManager& source_manager) {
  std::filesystem::path native_path = std::filesystem::path(path);
  if (!native_path.is_absolute()) {
    llvm::ErrorOr<std::string> cwd = source_manager.getFileManager()
                                         .getVirtualFileSystem()
                                         .getCurrentWorkingDirectory();
    QCHECK(cwd) << "unable to get cwd";
    native_path = std::filesystem::path(*cwd);
    native_path.append(path);
  }
  return native_path.lexically_normal();
}

// Converting from `SourceLocation` to a usable file location is non-trivial,
// see comments in-line for explanation.
LocationId GetLocationId(InMemoryIndex& index,
                         const clang::SourceManager& source_manager,
                         clang::SourceLocation start,
                         clang::SourceLocation end) {
  std::string path = "";
  uint32_t start_line = 0, end_line = 0;

  // If the location is inside a macro expansion, we want to first resolve it to
  // the source location (of the expansion). For example:
  //
  // 1: #define INNER_MACRO 1
  // 2: #define OUTER_MACRO INNER_MACRO
  // 3: OUTER_MACRO
  //
  // If we look at the reference to INNER_MACRO here, we'd want to see that it
  // is referenced from line 3, not from line 2.
  //
  // `getExpansionLoc` is the identity function if the location is not in an
  // expansion.
  start = source_manager.getExpansionLoc(start);
  end = source_manager.getExpansionLoc(end);

  // At this point, both of the `SourceLocations` that are valid should be file
  // locations. `getPresumedLoc` will then resolve these to meaningful file
  // locations.
  clang::PresumedLoc presumed_start =
      source_manager.getPresumedLoc(start, false);
  if (!presumed_start.isInvalid()) {
    path = presumed_start.getFilename();
    start_line = presumed_start.getLine();
    end_line = presumed_start.getLine();
  }

  clang::PresumedLoc presumed_end = source_manager.getPresumedLoc(end, false);
  if (!presumed_end.isInvalid()) {
    end_line = presumed_end.getLine();
  }

  if (end_line < start_line) {
    end_line = start_line;
  }

  if (IsRealPath(path)) {
    // This is a real file path, so normalize it.
    path = ToNormalizedAbsolutePath(path, source_manager);
  }
  return index.GetLocationId({path, start_line, end_line});
}

}  // namespace indexer
}  // namespace oss_fuzz
