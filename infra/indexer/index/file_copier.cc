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

#include "indexer/index/file_copier.h"

#include <filesystem>  // NOLINT
#include <string>
#include <system_error>  // NOLINT
#include <utility>
#include <vector>

#include "absl/container/flat_hash_set.h"
#include "absl/log/check.h"
#include "absl/log/log.h"
#include "absl/strings/match.h"
#include "absl/strings/string_view.h"
#include "absl/synchronization/mutex.h"

namespace oss_fuzz {
namespace indexer {

namespace {
void PreparePath(std::string& path) {
  if (!path.empty() && !path.ends_with('/')) {
    path.append("/");
  }

  CHECK(path.empty() || std::filesystem::path(path).is_absolute()) << path;
}
}  // namespace

FileCopier::FileCopier(absl::string_view base_path,
                       absl::string_view index_path,
                       const std::vector<std::string>& extra_paths,
                       bool dry_run)
    : base_path_(base_path),
      extra_paths_(extra_paths),
      index_path_(index_path),
      dry_run_(dry_run) {
  PreparePath(base_path_);
  for (std::string& extra_path : extra_paths_) {
    PreparePath(extra_path);
  }
}

std::string FileCopier::ToIndexPath(absl::string_view path) const {
  if (!path.starts_with('/')) {
    return std::string(path);
  }

  std::string result = std::string(path);
  if (!base_path_.empty() && absl::StartsWith(path, base_path_)) {
    result = path.substr(base_path_.size());
  } else {
    bool found = false;
    for (const auto& extra_path : extra_paths_) {
      if (!extra_path.empty() && absl::StartsWith(path, extra_path)) {
        found = true;
      }
    }
    CHECK(found) << "File outside of --source_dir and --extra_dirs: " << path;
  }
  return result;
}

void FileCopier::CopyFileIfNecessary(absl::string_view index_path) {
  if (index_path.empty() || index_path.starts_with('<')) {
    // Built-in header or a location lacking the filename.
    return;
  }

  std::filesystem::path src_path;
  std::filesystem::path dst_path;
  src_path = std::filesystem::path(index_path);
  if (src_path.is_absolute()) {
    dst_path =
        std::filesystem::path(index_path_) / "absolute" / index_path.substr(1);
  } else {
    src_path = std::filesystem::path(base_path_) / index_path;
    dst_path = std::filesystem::path(index_path_) / "relative" / index_path;
  }

  DLOG(INFO) << "From: " << src_path << "\n  To: " << dst_path << "\n";

  CHECK(std::filesystem::exists(src_path))
      << "Source file does not exist: " << index_path;

  bool should_copy = false;
  {
    absl::MutexLock lock(&mutex_);
    should_copy = indexed_files_.insert(dst_path).second;
  }

  if (should_copy && !dry_run_) {
    std::error_code error_code;
    // We can race on creating the destination directory structure, so silently
    // ignore errors here.
    (void)std::filesystem::create_directories(dst_path.parent_path(),
                                              error_code);

    // We cannot race on creating the same destination file.
    QCHECK(std::filesystem::copy_file(
        src_path, dst_path, std::filesystem::copy_options::overwrite_existing,
        error_code))
        << "Failed to copy file: " << src_path
        << " (error: " << error_code.message() << ")";
  }
}

}  // namespace indexer
}  // namespace oss_fuzz
