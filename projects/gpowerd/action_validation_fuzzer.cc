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
//##############################################################################

#include <stdint.h>
#include <stddef.h>
#include <memory>
#include <utility>

#include "action_validation.h"
#include "daemon_context.h"
#include "scheduler_interface.h"
#include "persistent_storage.h"
#include "safepower_agent.pb.h"
#include "safepower_agent_config.pb.h"
#include "system_state.pb.h"
#include "absl/time/time.h"
#include "absl/status/status.h"
#include "absl/status/statusor.h"

namespace safepower_agent {

class DummyScheduler : public SchedulerInterface {
 public:
  absl::Status PeriodicCall(absl::AnyInvocable<void()> fn,
                            absl::Duration interval,
                            absl::string_view name) override {
    return absl::OkStatus();
  }
  absl::Status DelayCall(absl::AnyInvocable<void() &&> fn,
                         absl::Duration wait_duration,
                         absl::string_view name) override {
    return absl::OkStatus();
  }
  absl::Status CancelCall(absl::string_view name) override {
    return absl::OkStatus();
  }
  absl::Status CancelAll() override {
    return absl::OkStatus();
  }
  absl::Status Shutdown() override {
    return absl::OkStatus();
  }
};

class DummyPersistentStorage : public PersistentStorageManager {
 public:
  absl::Status WriteSavedActionsChange(
      const safepower_agent_persistence_proto::SavedActions& actions) override {
    return absl::OkStatus();
  }
  absl::StatusOr<safepower_agent_persistence_proto::SavedActions>
  ReadSavedActions() override {
    return safepower_agent_persistence_proto::SavedActions();
  }
  absl::Status InitializeSavedActions() override {
    return absl::OkStatus();
  }
};

class DummyDaemonContext : public DaemonContext {
 public:
  DummyDaemonContext() : scheduler_(), storage_() {}
  
  uint64_t epoch_ms() override { return 0; }
  SchedulerInterface& scheduler() override { return scheduler_; }
  PersistentStorageManager& persistent_storage_manager() override { return storage_; }
  absl::StatusOr<safepower_agent_proto::BuildInfo> GetBuildInfo() const override {
    return safepower_agent_proto::BuildInfo();
  }

 private:
  DummyScheduler scheduler_;
  DummyPersistentStorage storage_;
};

}  // namespace safepower_agent

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  static safepower_agent::DummyDaemonContext* context = new safepower_agent::DummyDaemonContext();

  if (size < 4) return 0;
  // Use first 2 bytes for size of request
  uint16_t req_size = (data[0] << 8) | data[1];
  if (req_size > size - 2) return 0;
  
  safepower_agent_proto::StartActionRequest request;
  if (!request.ParseFromArray(data + 2, req_size)) {
    return 0;
  }
  
  safepower_agent_proto::SystemState initial_system_state;
  if (!initial_system_state.ParseFromArray(data + 2 + req_size, size - 2 - req_size)) {
    return 0;
  }
  
  absl::Time start_time = absl::FromUnixSeconds(1234567890);
  safepower_agent_config::ConditionValidationOptions options;
  options.set_max_boots(10);
  options.set_max_timeout_seconds(3600);
  std::string node_entity_tag = "node-1";
  if (!initial_system_state.node_state().empty()) {
    node_entity_tag = initial_system_state.node_state().begin()->first;
  }

  safepower_agent::ValidateRequest(request, node_entity_tag, initial_system_state, start_time, options);
  return 0;
}
