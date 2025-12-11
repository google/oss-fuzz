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
                       Behavior behavior, bool skip_missing_files)
    : base_path_(base_path),
      extra_paths_(extra_paths),
      index_path_(index_path),
      behavior_(behavior),
      skip_missing_files_(skip_missing_files) {
  if (behavior_ == Behavior::kNoOp) {
    return;
  }

  PreparePath(base_path_);
  for (std::string& extra_path : extra_paths_) {
    PreparePath(extra_path);
  }
}

std::string FileCopier::AbsoluteToIndexPath(absl::string_view path) const {
  CHECK(path.starts_with("/")) << "Absolute path expected: " << path;

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

void FileCopier::RegisterIndexedFile(absl::string_view index_path) {
  if (behavior_ == Behavior::kNoOp) {
    return;
  }

  absl::MutexLock lock(mutex_);
  indexed_files_.emplace(index_path);
}

void FileCopier::CopyIndexedFiles() {
  if (behavior_ == Behavior::kNoOp) {
    return;
  }

  absl::MutexLock lock(mutex_);

  for (const std::string& indexed_path : indexed_files_) {
    std::filesystem::path src_path = indexed_path;
    std::filesystem::path dst_path;
    if (src_path.is_absolute()) {
      dst_path = std::filesystem::path(index_path_) / "absolute" /
                 indexed_path.substr(1);
    } else {
      src_path = std::filesystem::path(base_path_) / indexed_path;
      dst_path = std::filesystem::path(index_path_) / "relative" / indexed_path;
    }

    if (!std::filesystem::exists(src_path)) {
      if (!skip_missing_files_) {
        LOG(QFATAL) << "Source file " << src_path
                   << " does not exist and skip_missing_files is false.";
      } else {
        LOG(WARNING) << "Skipping non-existent source file: " << src_path;
        continue;
      }
    }

    DLOG(INFO) << "\nFrom: " << src_path << "\n  To: " << dst_path << "\n";

    std::error_code error_code;
    // The destination directory may already exist, but report other errors.
    (void)std::filesystem::create_directories(dst_path.parent_path(),
                                              error_code);
    QCHECK(!error_code) << "Failed to create directory: "
                        << dst_path.parent_path()
                        << " (error: " << error_code.message() << ")";

    using std::filesystem::copy_options;
    const copy_options options = behavior_ == Behavior::kOverwriteExistingFiles
                                     ? copy_options::overwrite_existing
                                     : copy_options::none;
    std::filesystem::copy_file(src_path, dst_path, options, error_code);
    QCHECK(!error_code) << "Failed to copy file " << src_path << " to "
                        << dst_path << " (error: " << error_code.message()
                        << ")";
  }
}
}  // namespace indexer
}  // namespace oss_fuzz
