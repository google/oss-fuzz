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

#ifndef OSS_FUZZ_INFRA_INDEXER_FRONTEND_FRONTEND_H_
#define OSS_FUZZ_INFRA_INDEXER_FRONTEND_FRONTEND_H_

#include <memory>
#include <string>
#include <utility>
#include <vector>

#include "indexer/index/file_copier.h"
#include "indexer/merge_queue.h"
#include "absl/strings/string_view.h"
#include "clang/Tooling/ArgumentsAdjusters.h"
#include "clang/Tooling/Tooling.h"

namespace oss_fuzz {
namespace indexer {
namespace frontend_internal {
// Parses a command line string into a vector of arguments.
// This is used internally in GetIndexActions() to parse the
// --extra_compiler_args flag, exposed here for testing only.
std::vector<std::string> ParseCommandLine(absl::string_view commandLine);
}  // namespace frontend_internal

// Gets the index tool and arguments adjuster to be used with clang tooling to
// perform indexing on a compilation database.
std::vector<std::pair<std::unique_ptr<clang::tooling::FrontendActionFactory>,
                      clang::tooling::ArgumentsAdjuster>>
GetIndexActions(FileCopier& file_copier, MergeQueue& merge_queue);
}  // namespace indexer
}  // namespace oss_fuzz

#endif  // OSS_FUZZ_INFRA_INDEXER_FRONTEND_FRONTEND_H_
