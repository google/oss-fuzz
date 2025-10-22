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

#ifndef OSS_FUZZ_INFRA_INDEXER_QUEUE_STATE_H_
#define OSS_FUZZ_INFRA_INDEXER_QUEUE_STATE_H_

#include <atomic>
#include <string>

namespace oss_fuzz {
namespace indexer {
// Since the IndexQueues and MergeQueues have a non-trivial state space, and run
// across multiple threads, we have a small thread-safe state-machine used to
// ensure that only valid state transitions are permitted.
//
// The logic is similar for both queue types, for illustration the allowed
// transitions for an IndexQueue are:
//
//   kNotAdded -> kAdded     on queue->Add()
//             -> kWaiting   on queue->WaitUntilComplete() entry
//             -> kDestroyed on ~queue
//
//   kAdded    -> kWaiting   on queue->WaitUntilComplete() entry
//
//   kWaiting  -> kFinished    on queue->WaitUntilComplete() exit
//
//   kFinished -> kDestroyed on ~queue
//
// And for a MergeQueue:
//
//   kNotAdded -> kAdded     on queue->Add()
//             -> kWaiting   on queue->WaitUntilComplete() entry
//             -> kDestroyed on ~queue
//
//   kAdded    -> kWaiting   on queue->WaitUntilComplete() entry
//
//   kWaiting  -> kFinished    on queue->WaitUntilComplete() exit
//
//   kFinished -> kTaken     on queue->TakeIndex()
//
//   kTaken    -> kDestroyed on ~queue
//
// Attempting any other transitions will result in a CHECK failure.
class QueueState {
 public:
  enum class QueueType { kIndex, kMerge };
  explicit QueueState(QueueType type);

  void SetAdded();
  void SetWaiting();
  void SetFinished(bool cancelled = false);
  void SetTaken();
  void SetDestroyed();

  bool IsWaiting() const;
  bool IsFinished() const;

 private:
  enum State {
    kNotAdded = 1,
    kAdded = 1 << 1,
    kWaiting = 1 << 2,
    // Note that ordering is important here, and all states following kFinished
    // are considered "finished".
    kFinished = 1 << 3,
    kTaken = 1 << 4,
    kDestroyed = 1 << 5,
  };

  std::string StateToString(State state);
  void Advance(State from, State to);

  const QueueType type_;
  std::atomic<State> state_ = kNotAdded;
};
}  // namespace indexer
}  // namespace oss_fuzz

#endif  // OSS_FUZZ_INFRA_INDEXER_QUEUE_STATE_H_
