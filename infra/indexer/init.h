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

// This is only built/included in the open source indexer.
#ifndef OSS_FUZZ_INFRA_INDEXER_INIT_H_
#define OSS_FUZZ_INFRA_INDEXER_INIT_H_

#include "absl/flags/parse.h"
#include "absl/flags/usage.h"
#include "absl/log/initialize.h"
#include "absl/strings/string_view.h"

void InitGoogle(absl::string_view usage, int* argc, char*** argv,
                bool remove_flags) {
  absl::InitializeLog();
  absl::SetProgramUsageMessage(*argv[0]);
  absl::ParseCommandLine(*argc, *argv);
}

void InitGoogleExceptChangeRootAndUser(absl::string_view usage, int* argc,
                                       char*** argv, bool remove_flags) {
  InitGoogle(usage, argc, argv, remove_flags);
}

#endif  // OSS_FUZZ_INFRA_INDEXER_INIT_H_
