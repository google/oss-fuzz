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

#ifndef OSS_FUZZ_INFRA_INDEXER_INDEX_FILE_COPIER_H_
#define OSS_FUZZ_INFRA_INDEXER_INDEX_FILE_COPIER_H_

#include <filesystem>  // NOLINT
#include <string>
#include <vector>

#include "absl/base/thread_annotations.h"
#include "absl/container/flat_hash_set.h"
#include "absl/strings/string_view.h"
#include "absl/synchronization/mutex.h"

namespace oss_fuzz {
namespace indexer {

// FileCopier tracks the source code files that have been copied across all
// InMemoryIndexes for the current project. The same FileCopier is shared by
// all InMemoryIndexes for the current project.
class FileCopier {
 public:
  enum class Behavior {
    kNoOp,
    kFailOnExistingFiles,
    kOverwriteExistingFiles,
  };

  FileCopier(absl::string_view base_path, absl::string_view index_path,
             const std::vector<std::string>& extra_paths,
             Behavior behavior = Behavior::kFailOnExistingFiles,
             bool skip_missing_files = false);
  FileCopier(const FileCopier&) = delete;

  // Takes an absolute path. Rewrites this path into the representation it will
  // have in the index (relative if within the source tree and absolute
  // otherwise).
  std::string AbsoluteToIndexPath(absl::string_view path) const;

  // `index_path` is expected to be produced by `ToIndexPath`.
  void RegisterIndexedFile(absl::string_view index_path);

  // Single-threaded.
  void CopyIndexedFiles();

 private:
  std::string base_path_;
  std::vector<std::string> extra_paths_;
  const std::filesystem::path index_path_;
  const Behavior behavior_;
  const bool skip_missing_files_;

  absl::Mutex mutex_;
  absl::flat_hash_set<std::string> indexed_files_ ABSL_GUARDED_BY(mutex_);
};

}  // namespace indexer
}  // namespace oss_fuzz

#endif  // OSS_FUZZ_INFRA_INDEXER_INDEX_FILE_COPIER_H_
