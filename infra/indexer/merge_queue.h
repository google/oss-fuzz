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

#ifndef OSS_FUZZ_INFRA_INDEXER_MERGE_QUEUE_H_
#define OSS_FUZZ_INFRA_INDEXER_MERGE_QUEUE_H_

#include <memory>

#include "indexer/index/in_memory_index.h"

namespace oss_fuzz {
namespace indexer {
// Interface for the merging queue.
//
// The `MergeQueue::Create` class function should be used to create an
// appropriate queue instance for the provided parameters.
class MergeQueue {
 public:
  virtual ~MergeQueue();

  // Add implementations are required to be thread-safe, and support being
  // called from multiple threads in parallel.
  virtual void Add(std::unique_ptr<InMemoryIndex> index) = 0;

  // WaitUntilComplete should ensure that all currently-queued merge tasks are
  // complete before returning. It does not provide any guarantee that all
  // future merge tasks are complete, so it should be ensured that all merge
  // tasks have been queued (by a call to Add) before this is used.
  virtual void WaitUntilComplete() = 0;

  // Cancel should ensure that all currently queued merge tasks are cancelled
  // or completed before returning. After cancellation, further attempts to add
  // new merge tasks is considered a bug (and will result in a crash).
  virtual void Cancel() = 0;

  // TakeIndex should only be called after WaitUntilComplete has been called.
  // It takes ownership of the completed merged index.
  virtual std::unique_ptr<InMemoryIndex> TakeIndex() = 0;

  static std::unique_ptr<MergeQueue> Create(int queue_count = 1,
                                            int queue_length = 16);
};
}  // namespace indexer
}  // namespace oss_fuzz

#endif  // OSS_FUZZ_INFRA_INDEXER_MERGE_QUEUE_H_
