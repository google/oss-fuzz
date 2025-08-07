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

#include <sched.h>

#include <filesystem>  // NOLINT
#include <memory>
#include <string>
#include <system_error>  // NOLINT
#include <utility>
#include <vector>

#include "init.h"
#include "indexer/frontend/frontend.h"
#include "indexer/index/file_copier.h"
#include "indexer/index/in_memory_index.h"
#include "indexer/index/sqlite.h"
#include "indexer/merge_queue.h"
#include "absl/flags/flag.h"
#include "absl/log/check.h"
#include "absl/log/log.h"
#include "absl/strings/string_view.h"
#include "clang/Tooling/AllTUsExecution.h"
#include "clang/Tooling/CompilationDatabase.h"
#include "clang/Tooling/Tooling.h"
#include "llvm/Support/Error.h"

ABSL_FLAG(std::string, source_dir, "", "Source directory");
ABSL_FLAG(std::string, build_dir, "", "Build directory");
ABSL_FLAG(std::string, index_dir, "",
          "Output index file directory (should be empty if it exists)");
ABSL_FLAG(std::vector<std::string>, extra_dirs, {"/"},
          "Additional source directory/-ies (comma-separated)");
ABSL_FLAG(std::string, dry_run_regex, "",
          "If specified, dry-run only on files matching this (POSIX-like) "
          "`llvm::Regex` and don't store the index");
ABSL_FLAG(int, index_threads, 4, "Number of parallel indexing threads");
ABSL_FLAG(int, merge_queues, 1, "Number of parallel merge queues");
ABSL_FLAG(int, merge_queue_size, 16, "Length of merge queues");
ABSL_FLAG(bool, ignore_indexing_errors, false, "Ignore indexing errors");

int main(int argc, char** argv) {
  using oss_fuzz::indexer::InMemoryIndex;
  using oss_fuzz::indexer::MergeQueue;
  using clang::tooling::AllTUsToolExecutor;
  using clang::tooling::CompilationDatabase;

#ifdef NO_CHANGE_ROOT_AND_USER
  // When running inside a container, we cannot drop privileges.
  InitGoogleExceptChangeRootAndUser(argv[0], &argc, &argv, true);
#else
  InitGoogle(absl::NullSafeStringView(argv[0]), &argc, &argv, true);
#endif

  const std::string& source_dir = absl::GetFlag(FLAGS_source_dir);
  const std::string& build_dir = absl::GetFlag(FLAGS_build_dir);
  const std::string& index_dir = absl::GetFlag(FLAGS_index_dir);
  const std::vector<std::string>& extra_dirs = absl::GetFlag(FLAGS_extra_dirs);
  auto index_path = std::filesystem::path(index_dir) / "db.sqlite";

#ifndef NDEBUG
  LOG(ERROR) << "indexer is built without optimisations. Use 'blaze run -c opt'"
             << " for indexing larger codebases, or this will be extra slow.";
#endif

  std::string error;
  auto db = CompilationDatabase::autoDetectFromDirectory(build_dir, error);
  if (!db) {
    LOG(ERROR) << "Failed to load compilation database: " << error;
    return 1;
  }

  const std::string& dry_run_regex = absl::GetFlag(FLAGS_dry_run_regex);
  if (!dry_run_regex.empty()) {
    clang::tooling::Filter.setValue(dry_run_regex);
  }

  oss_fuzz::indexer::FileCopier file_copier(source_dir, index_dir, extra_dirs);

  std::unique_ptr<MergeQueue> merge_queue = MergeQueue::Create(
      absl::GetFlag(FLAGS_merge_queues), absl::GetFlag(FLAGS_merge_queue_size));

  auto executor = AllTUsToolExecutor(*db, absl::GetFlag(FLAGS_index_threads));
  auto index_actions =
      oss_fuzz::indexer::GetIndexActions(file_copier, *merge_queue);
  auto index_error = executor.execute(index_actions);
  if (index_error) {
    LOG(ERROR) << "Indexing errors:\n"
               << llvm::toString(std::move(index_error));
    if (!absl::GetFlag(FLAGS_ignore_indexing_errors)) {
      merge_queue->Cancel();
      std::error_code ignored_error_code;
      std::filesystem::remove_all(std::filesystem::path(index_dir),
                                  ignored_error_code);
      return 1;
    }
  }

  merge_queue->WaitUntilComplete();
  auto index = merge_queue->TakeIndex();
  if (!index) {
    LOG(ERROR) << "Failed to create index";
    std::error_code ignored_error_code;
    std::filesystem::remove_all(std::filesystem::path(index_dir),
                                ignored_error_code);
    return 1;
  }

  if (!dry_run_regex.empty()) {
    return 0;
  }

  LOG(INFO) << "copying files";
  file_copier.CopyIndexedFiles();

  LOG(INFO) << "exporting index";
  auto flat_index = std::move(*index).Export();

  bool saved = SaveAsSqlite(flat_index, index_path);
  return saved ? 0 : 1;
}
