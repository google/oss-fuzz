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

#ifndef OSS_FUZZ_INFRA_INDEXER_FRONTEND_COMMON_H_
#define OSS_FUZZ_INFRA_INDEXER_FRONTEND_COMMON_H_

#include <string>

#include "indexer/index/in_memory_index.h"
#include "indexer/index/types.h"
#include "absl/strings/string_view.h"
#include "clang/Basic/SourceLocation.h"
#include "clang/Basic/SourceManager.h"

namespace oss_fuzz {
namespace indexer {
// Converts a source-level `path` into a normalized absolute form suitable for
// passing to the indexer as a location path.
std::string ToNormalizedAbsolutePath(
    absl::string_view path, const clang::SourceManager& source_manager);

// Converts a pair of `SourceLocation` to a `LocationId` for a location in the
// index.
LocationId GetLocationId(InMemoryIndex& index,
                         const clang::SourceManager& source_manager,
                         clang::SourceLocation start,
                         clang::SourceLocation end);
}  // namespace indexer
}  // namespace oss_fuzz

#endif  // OSS_FUZZ_INFRA_INDEXER_FRONTEND_COMMON_H_
