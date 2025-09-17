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
#include <optional>
#include <string>
#include <system_error>  // NOLINT
#include <utility>
#include <vector>

#include "init.h"
#include "indexer/frontend/frontend.h"
#include "indexer/index/file_copier.h"
#include "indexer/index/in_memory_index.h"
#include "indexer/index/sqlite.h"
#include "indexer/index/types.h"
#include "indexer/merge_queue.h"
#include "absl/base/optimization.h"
#include "absl/flags/flag.h"
#include "absl/log/check.h"
#include "absl/log/log.h"
#include "absl/strings/string_view.h"
#include "clang/Tooling/AllTUsExecution.h"
#include "clang/Tooling/CompilationDatabase.h"
#include "clang/Tooling/Tooling.h"
#include "llvm/Support/Error.h"

// For value meanings, see the --incremental flag documentation.
enum class IncrementalMode { kDisabled, kBootstrap, kUpdate };

// Parses an `IncrementalMode` from the command line flag value `text`.
// Returns `true` and sets `*mode` on success; returns `false` and sets `*error`
// on failure.
bool AbslParseFlag(absl::string_view text, IncrementalMode* mode,
                   std::string* error) {
  if (text == "disabled") {
    *mode = IncrementalMode::kDisabled;
    return true;
  }
  if (text == "bootstrap") {
    *mode = IncrementalMode::kBootstrap;
    return true;
  }
  if (text == "update") {
    *mode = IncrementalMode::kUpdate;
    return true;
  }
  *error = "unknown value (expected one of 'disabled', 'bootstrap', 'update')";
  return false;
}

std::string AbslUnparseFlag(IncrementalMode mode) {
  switch (mode) {
    case IncrementalMode::kDisabled:
      return "disabled";
    case IncrementalMode::kBootstrap:
      return "bootstrap";
    case IncrementalMode::kUpdate:
      return "update";
  }
  ABSL_UNREACHABLE();
}

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
ABSL_FLAG(IncrementalMode, incremental, IncrementalMode::kDisabled,
          "Control incremental mode ('disabled': the database will have no"
          " incremental indexing support, saving space;"
          " 'bootstrap': create a new database with incremental indexing"
          " support, overwriting the existing one if any;"
          " 'update': given an existing database - failing if none is present -"
          " reindex only those translation units that are listed in the"
          " compilation database, retaining all the other TUs' symbols)."
          " Note: no source files are ever deleted, only database entries");

int main(int argc, char** argv) {
  using oss_fuzz::indexer::FlatIndex;
  using oss_fuzz::indexer::InitializeSqlite;
  using oss_fuzz::indexer::InMemoryIndex;
  using oss_fuzz::indexer::LoadFromSqlite;
  using oss_fuzz::indexer::MergeQueue;
  using oss_fuzz::indexer::SaveAsSqlite;
  using clang::tooling::AllTUsToolExecutor;
  using clang::tooling::CompilationDatabase;
  using clang::tooling::CompileCommand;

#ifdef NO_CHANGE_ROOT_AND_USER
  // When running inside a container, we cannot drop privileges.
  InitGoogleExceptChangeRootAndUser(argv[0], &argc, &argv, true);
#else
  InitGoogle(argv[0], &argc, &argv, true);
#endif

  if (!InitializeSqlite()) {
    LOG(ERROR) << "Failed to inialize SQLite";
    return 1;
  }

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

  const IncrementalMode incremental_mode = absl::GetFlag(FLAGS_incremental);
  const bool incremental_update = incremental_mode == IncrementalMode::kUpdate;
  oss_fuzz::indexer::FileCopier file_copier(source_dir, index_dir, extra_dirs,
                                            /*exist_ok=*/incremental_update);

  std::unique_ptr<MergeQueue> merge_queue = MergeQueue::Create(
      absl::GetFlag(FLAGS_merge_queues), absl::GetFlag(FLAGS_merge_queue_size));

  if (incremental_update) {
    const std::optional<FlatIndex> existing_index = LoadFromSqlite(index_path);
    CHECK(existing_index) << "--incremental=update requires an existing index";

    std::vector<std::string> excluded_tu_absolute_paths;
    for (const CompileCommand& compile_command : db->getAllCompileCommands()) {
      std::filesystem::path path(compile_command.Filename);
      if (!path.is_absolute()) {
        path = compile_command.Directory / path;
        CHECK(path.is_absolute());
      }
      excluded_tu_absolute_paths.emplace_back(path);
    }

    merge_queue->Add(std::make_unique<InMemoryIndex>(
        file_copier, *existing_index, excluded_tu_absolute_paths));
  }

  auto executor = AllTUsToolExecutor(*db, absl::GetFlag(FLAGS_index_threads));
  const bool support_incremental_indexing =
      incremental_mode != IncrementalMode::kDisabled;
  auto index_actions = oss_fuzz::indexer::GetIndexActions(
      file_copier, *merge_queue, support_incremental_indexing);
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
