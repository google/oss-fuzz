// Copyright 2026 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
////////////////////////////////////////////////////////////////////////////////

#include <stdint.h>
#include <stddef.h>
#include <string>
#include <tuple>
#include <vector>

#include "condition.h"
#include "action.pb.h"
#include "system_state.pb.h"
#include "absl/time/time.h"
#include <fuzzer/FuzzedDataProvider.h>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  FuzzedDataProvider provider(data, size);

  // Split the data into two parts for the two protobufs
  // We use a 50/50 split of the remaining bytes
  size_t remaining = provider.remaining_bytes();
  if (remaining < 2) {
    return 0;
  }
  size_t size1 = provider.ConsumeIntegralInRange<size_t>(0, remaining - 1);
  std::string proto1_bytes = provider.ConsumeBytesAsString(size1);
  std::string proto2_bytes = provider.ConsumeRemainingBytesAsString();

  safepower_agent_proto::Condition condition;
  if (!condition.ParseFromString(proto1_bytes)) {
    return 0;
  }

  safepower_agent_proto::SystemState system_state;
  if (!system_state.ParseFromString(proto2_bytes)) {
    return 0;
  }

  // Generate some timestamps
  absl::Time start_time = absl::FromUnixSeconds(1719657600); // Static base time
  absl::Time current_time = start_time + absl::Seconds(provider.ConsumeIntegralInRange<int64_t>(0, 3600 * 24));

  // Call the target API
  auto [status, matches] = safepower_agent::Condition::Matches(
      condition, system_state, start_time, current_time);

  return 0;
}
