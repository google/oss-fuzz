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

#include "indexer/queue_state.h"

#include <atomic>
#include <string>
#include <vector>

#include "absl/log/check.h"
#include "absl/strings/str_join.h"

namespace oss_fuzz {
namespace indexer {
QueueState::QueueState(QueueType type) : type_(type) {}

void QueueState::SetAdded() {
  Advance(static_cast<State>(kNotAdded | kAdded), kAdded);
}

void QueueState::SetWaiting() {
  Advance(static_cast<State>(kNotAdded | kAdded), kWaiting);
}

void QueueState::SetFinished(bool cancelled) {
  if (cancelled) {
    Advance(static_cast<State>(kNotAdded | kAdded | kWaiting), kFinished);
  } else {
    Advance(kWaiting, kFinished);
  }
}

void QueueState::SetTaken() {
  CHECK(type_ == QueueType::kMerge);
  Advance(kFinished, kTaken);
}

void QueueState::SetDestroyed() {
  if (type_ == QueueType::kIndex) {
    Advance(static_cast<State>(kNotAdded | kFinished), kDestroyed);
  } else {
    Advance(static_cast<State>(kNotAdded | kTaken), kDestroyed);
  }
}

bool QueueState::IsWaiting() const {
  return state_.load(std::memory_order_acquire) == kWaiting;
}

bool QueueState::IsFinished() const {
  return state_.load(std::memory_order_acquire) >= kFinished;
}

std::string QueueState::StateToString(State state) {
  std::vector<std::string> parts;
  if (state & State::kNotAdded) {
    parts.push_back("kNotAdded");
  }
  if (state & State::kAdded) {
    parts.push_back("kAdded");
  }
  if (state & State::kWaiting) {
    parts.push_back("kWaiting");
  }
  if (state & State::kFinished) {
    parts.push_back("kFinished");
  }
  if (state & State::kTaken) {
    parts.push_back("kTaken");
  }
  if (state & State::kDestroyed) {
    parts.push_back("kDestroyed");
  }
  return absl::StrJoin(parts, "|");
}

void QueueState::Advance(State from, State to) {
  State current = state_.load(std::memory_order_acquire);
  CHECK_NE((current & from), 0)
      << "Found " << StateToString(current) << " while advancing "
      << StateToString(from) << " -> " << StateToString(to);
  if (current != to) {
    while (!state_.compare_exchange_weak(current, to, std::memory_order_release,
                                         std::memory_order_relaxed)) {
      CHECK_NE((current & from), 0)
          << "Found " << StateToString(current) << " while advancing "
          << StateToString(from) << " -> " << StateToString(to);
    }
  }
}
}  // namespace indexer
}  // namespace oss_fuzz
