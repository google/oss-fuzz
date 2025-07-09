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

#include "indexer/frontend/frontend.h"

#include <cctype>
#include <cstddef>
#include <cstdlib>
#include <memory>
#include <string>
#include <utility>
#include <vector>

#include "indexer/frontend/index_action.h"
#include "indexer/index/file_copier.h"
#include "indexer/merge_queue.h"
#include "absl/flags/flag.h"
#include "absl/strings/match.h"
#include "absl/strings/string_view.h"
#include "clang/Tooling/ArgumentsAdjusters.h"
#include "clang/Tooling/Tooling.h"
#include "llvm/ADT/StringRef.h"

ABSL_FLAG(std::string, extra_compiler_args, "", "Extra compiler flags");

namespace oss_fuzz {
namespace indexer {
namespace frontend_internal {
std::vector<std::string> ParseCommandLine(absl::string_view commandLine) {
  std::vector<std::string> args;
  std::string currentArg;
  bool inSingleQuotes = false;
  bool inDoubleQuotes = false;
  bool escaped = false;
  for (char c : commandLine) {
    if (c == '\\' && inDoubleQuotes) {
      escaped = true;
      continue;
    }
    if (c == '\'' && !inDoubleQuotes && !escaped) {
      if (inSingleQuotes) {
        inSingleQuotes = false;
        args.push_back(currentArg);
        currentArg.clear();
      } else {
        inSingleQuotes = true;
      }
    } else if (c == '"' && !inSingleQuotes && !escaped) {
      if (inDoubleQuotes) {
        inDoubleQuotes = false;
        args.push_back(currentArg);
        currentArg.clear();
      } else {
        inDoubleQuotes = true;
      }
    } else if (std::isspace(c) && !inSingleQuotes && !inDoubleQuotes) {
      if (!currentArg.empty()) {
        args.push_back(currentArg);
        currentArg.clear();
      }
    } else {
      currentArg += c;
    }
    escaped = false;
  }
  if (!currentArg.empty()) {
    args.push_back(currentArg);
  }
  return args;
}
}  // namespace frontend_internal

namespace {
// We need to strip clang-specific arguments from the command line, as these are
// usually invocations of clang plugins, which will not be present in our build
// of clang/llvm.
clang::tooling::CommandLineArguments RemoveClangArgumentsAdjuster(
    const clang::tooling::CommandLineArguments& arguments, llvm::StringRef) {
  clang::tooling::CommandLineArguments result;
  for (size_t i = 0; i < arguments.size(); ++i) {
    if (arguments[i] == "-Xclang") {
      ++i;
    } else if (absl::StartsWith(arguments[i], "-cfg=") ||
               absl::StartsWith(arguments[i], "-exec_root=")) {
      // Also skip these arguments, it's reclient...
    } else if (absl::EndsWith(arguments[i], ".o.d")) {
      // Also skip these arguments, these are there to create dependencies
      // between build actions.
    } else {
      result.push_back(arguments[i]);
    }
  }
  return result;
}

clang::tooling::CommandLineArguments ExtraArgumentsAdjuster(
    const clang::tooling::CommandLineArguments& arguments, llvm::StringRef) {
  clang::tooling::CommandLineArguments result = arguments;
  std::vector<std::string> extra_args = frontend_internal::ParseCommandLine(
      absl::GetFlag(FLAGS_extra_compiler_args));
  result.insert(result.end(), extra_args.begin(), extra_args.end());
  return result;
}
}  // namespace

// Gets the index tool and arguments adjuster to be used with clang tooling to
// perform indexing on a compilation database.
std::vector<std::pair<std::unique_ptr<clang::tooling::FrontendActionFactory>,
                      clang::tooling::ArgumentsAdjuster>>
GetIndexActions(FileCopier& file_copier, MergeQueue& merge_queue) {
  std::vector<std::pair<std::unique_ptr<clang::tooling::FrontendActionFactory>,
                        clang::tooling::ArgumentsAdjuster>>
      actions;
  auto index_action =
      std::make_unique<IndexActionFactory>(file_copier, merge_queue);
  auto adjuster = clang::tooling::combineAdjusters(RemoveClangArgumentsAdjuster,
                                                   ExtraArgumentsAdjuster);
  actions.push_back(
      std::make_pair(std::move(index_action), std::move(adjuster)));
  return actions;
}
}  // namespace indexer
}  // namespace oss_fuzz
