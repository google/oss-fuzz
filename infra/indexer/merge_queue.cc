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

#include "indexer/merge_queue.h"

#include <atomic>
#include <cstddef>
#include <memory>
#include <queue>
#include <thread>  // NOLINT
#include <utility>
#include <vector>

#include "indexer/index/in_memory_index.h"
#include "indexer/queue_state.h"
#include "absl/base/thread_annotations.h"
#include "absl/log/check.h"
#include "absl/synchronization/mutex.h"

namespace oss_fuzz {
namespace indexer {
MergeQueue::~MergeQueue() = default;

// Single threaded implementation of the MergeQueue interface, backed by a
// ManagedQueue merging into a single owned InMemoryIndex.
class SingleThreadMergeQueue : public MergeQueue {
 public:
  explicit SingleThreadMergeQueue(int queue_limit = 16);
  ~SingleThreadMergeQueue() override
      ABSL_LOCKS_EXCLUDED(queue_mutex_, index_mutex_);

  void Add(std::unique_ptr<InMemoryIndex> index) override
      ABSL_LOCKS_EXCLUDED(queue_mutex_);
  void WaitUntilComplete() override;
  void Cancel() override;
  std::unique_ptr<InMemoryIndex> TakeIndex() override
      ABSL_LOCKS_EXCLUDED(index_mutex_);

 private:
  bool WaitForWriting() ABSL_EXCLUSIVE_LOCKS_REQUIRED(queue_mutex_);
  bool WaitForReading() ABSL_EXCLUSIVE_LOCKS_REQUIRED(queue_mutex_);

  void ThreadFunction() ABSL_LOCKS_EXCLUDED(queue_mutex_, index_mutex_);

  absl::Mutex index_mutex_;
  std::unique_ptr<InMemoryIndex> index_ ABSL_GUARDED_BY(index_mutex_);

  const int queue_limit_;
  absl::Mutex queue_mutex_;
  QueueState state_ ABSL_GUARDED_BY(queue_mutex_);
  std::queue<std::unique_ptr<InMemoryIndex>> queue_
      ABSL_GUARDED_BY(queue_mutex_);

  std::jthread thread_;
};

SingleThreadMergeQueue::SingleThreadMergeQueue(int queue_limit)
    : index_(nullptr),
      queue_limit_(queue_limit),
      state_(QueueState::QueueType::kMerge) {
  thread_ = std::jthread(&SingleThreadMergeQueue::ThreadFunction, this);
}

SingleThreadMergeQueue::~SingleThreadMergeQueue() { state_.SetDestroyed(); }

bool SingleThreadMergeQueue::WaitForWriting() {
  return state_.IsWaiting() || state_.IsFinished() ||
         queue_.size() < queue_limit_;
}

bool SingleThreadMergeQueue::WaitForReading() {
  return state_.IsWaiting() || state_.IsFinished() || !queue_.empty();
}

void SingleThreadMergeQueue::ThreadFunction() {
  while (true) {
    std::unique_ptr<InMemoryIndex> index_to_merge = nullptr;

    {
      absl::MutexLock queue_lock(queue_mutex_);
      queue_mutex_.Await(
        absl::Condition(this, &SingleThreadMergeQueue::WaitForReading)
      );

      // Either the queue has finished, or the queue is empty and the caller is
      // waiting for us to finish.
      if (state_.IsFinished() || queue_.empty()) {
        return;
      }

      index_to_merge = std::move(queue_.front());
      queue_.pop();
    }  // Drop queue_mutex_

    if (index_to_merge) {
      absl::MutexLock index_lock(index_mutex_);
      if (!index_) {
        index_ = std::move(index_to_merge);
      } else {
        index_->Merge(*index_to_merge);
        index_to_merge.reset();
      }
    }
  }
}

void SingleThreadMergeQueue::Add(std::unique_ptr<InMemoryIndex> new_index) {
  absl::MutexLock queue_lock(queue_mutex_);
  state_.SetAdded();
  queue_mutex_.Await(
      absl::Condition(this, &SingleThreadMergeQueue::WaitForWriting));
  if (!state_.IsFinished()) {
    queue_.push(std::move(new_index));
  }
}

void SingleThreadMergeQueue::WaitUntilComplete() {
  {
    absl::MutexLock queue_lock(queue_mutex_);
    state_.SetWaiting();
  }

  thread_.join();

  {
    absl::MutexLock queue_lock(queue_mutex_);
    state_.SetFinished();
  }
}

void SingleThreadMergeQueue::Cancel() {
  {
    absl::MutexLock queue_lock(queue_mutex_);
    state_.SetFinished(/*cancelled=*/true);
  }

  thread_.join();

  (void)TakeIndex();
}

std::unique_ptr<InMemoryIndex> SingleThreadMergeQueue::TakeIndex() {
  {
    absl::MutexLock queue_lock(queue_mutex_);
    state_.SetTaken();
  }

  absl::MutexLock index_lock(index_mutex_);
  return std::move(index_);
}

// Parallel merge queue implementation which round-robin schedules incoming
// merge tasks onto one-of-N internal SingleThreadMergeQueues, and then once
// indexing is complete does a parallel merge of those queues to produce a
// single result index.
class ParallelMergeQueue : public MergeQueue {
 public:
  explicit ParallelMergeQueue(int queue_count, int queue_limit = 16);
  ~ParallelMergeQueue() override;

  void Add(std::unique_ptr<InMemoryIndex> index) override;
  void WaitUntilComplete() override;
  void Cancel() override;
  std::unique_ptr<InMemoryIndex> TakeIndex() override;

 private:
  QueueState state_;
  std::atomic<size_t> next_queue_;
  std::vector<std::unique_ptr<SingleThreadMergeQueue>> queues_;
};

ParallelMergeQueue::ParallelMergeQueue(int queue_count, int queue_limit)
    : state_(QueueState::QueueType::kMerge), next_queue_(0) {
  for (int i = 0; i < queue_count; ++i) {
    queues_.emplace_back(std::make_unique<SingleThreadMergeQueue>(queue_limit));
  }
}

ParallelMergeQueue::~ParallelMergeQueue() { state_.SetDestroyed(); }

void ParallelMergeQueue::Add(std::unique_ptr<InMemoryIndex> index) {
  state_.SetAdded();
  size_t queue_index = next_queue_.fetch_add(1, std::memory_order_relaxed);
  queues_[queue_index % queues_.size()]->Add(std::move(index));
}

void ParallelMergeQueue::WaitUntilComplete() {
  state_.SetWaiting();
  while (queues_.size() > 1) {
    auto merge_into = std::move(queues_.back());
    queues_.pop_back();

    auto merge_from = std::move(queues_.back());
    queues_.pop_back();

    merge_from->WaitUntilComplete();
    merge_into->Add(merge_from->TakeIndex());

    queues_.push_back(std::move(merge_into));
  }

  CHECK_EQ(queues_.size(), 1);
  queues_[0]->WaitUntilComplete();
  state_.SetFinished();
}

void ParallelMergeQueue::Cancel() {
  state_.SetFinished(/*cancelled=*/true);
  for (auto& queue : queues_) {
    queue->Cancel();
  }
  state_.SetTaken();
}

std::unique_ptr<InMemoryIndex> ParallelMergeQueue::TakeIndex() {
  state_.SetTaken();
  return queues_[0]->TakeIndex();
}

// static
std::unique_ptr<MergeQueue> MergeQueue::Create(int queue_count,
                                               int queue_length) {
  if (queue_count == 1) {
    return std::make_unique<SingleThreadMergeQueue>(queue_length);
  } else {
    return std::make_unique<ParallelMergeQueue>(queue_count, queue_length);
  }
}
}  // namespace indexer
}  // namespace oss_fuzz
