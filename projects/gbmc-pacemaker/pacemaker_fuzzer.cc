/*
 * Copyright 2026 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <fuzzer/FuzzedDataProvider.h>
#include <memory>
#include <string>


#include "tlbmc/pacemaker/pacemaker.h"
#include "absl/status/statusor.h"
#include "absl/time/time.h"
#include "absl/synchronization/mutex.h"
#include "absl/log/initialize.h"
#include "absl/log/globals.h"

namespace milotic_tlbmc {

class FuzzedShellCommandExecutor : public ShellCommandExecutor {
 public:
  void SetFDP(FuzzedDataProvider* fdp) {
    absl::MutexLock lock(&mutex_);
    fdp_ = fdp;
  }

  absl::StatusOr<std::string> Execute(const std::string& command) override {
    absl::MutexLock lock(&mutex_);
    if (!fdp_) return "";
    if (fdp_->ConsumeBool()) {
      return absl::InternalError("Simulated shell error");
    }
    return fdp_->ConsumeRandomLengthString(256);
  }

 private:
  FuzzedDataProvider* fdp_ ABSL_GUARDED_BY(mutex_) = nullptr;
  absl::Mutex mutex_;
};

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  static bool initialized = []() {
    absl::InitializeLog();
    absl::SetMinLogLevel(absl::LogSeverityAtLeast::kFatal);
    return true;
  }();

  FuzzedDataProvider fdp(data, size);

  auto executor = std::make_unique<FuzzedShellCommandExecutor>();
  auto* raw_executor = executor.get();
  raw_executor->SetFDP(&fdp);

  // Fuzz Pacemaker exclusively
  auto pacemaker = Pacemaker::Create(absl::Milliseconds(100), std::move(executor));

  // Exercise main health checks workflow
  (void)pacemaker->PerformChecks();
  (void)pacemaker->GetMonitoringData();

  // Exercise individual helper functions with fuzzed parameters
  std::string proc_name = fdp.ConsumeRandomLengthString(64);
  (void)pacemaker->GetPid(proc_name);
  (void)pacemaker->GetCpuUsage(proc_name);
  (void)pacemaker->GetLastActiveTimestamp(proc_name);
  (void)pacemaker->IsServiceActive(proc_name);
  (void)pacemaker->RestartService(proc_name);

  int port = fdp.ConsumeIntegral<int>();
  (void)pacemaker->IsPortListening(port);

  int pid = fdp.ConsumeIntegral<int>();
  (void)pacemaker->GetMemoryUsage(pid);

  uint8_t err_raw = fdp.ConsumeIntegral<uint8_t>();
  pacemaker->RecordError(static_cast<ErrorType>(err_raw % 5));

  (void)pacemaker->GetMonitoringData();

  raw_executor->SetFDP(nullptr);
  return 0;
}

}  // namespace milotic_tlbmc
