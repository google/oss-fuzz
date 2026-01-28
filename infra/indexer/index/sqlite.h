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

#ifndef OSS_FUZZ_INFRA_INDEXER_INDEX_SQLITE_H_
#define OSS_FUZZ_INFRA_INDEXER_INDEX_SQLITE_H_

#include <string>

#include "indexer/index/types.h"

namespace oss_fuzz {
namespace indexer {
bool SaveAsSqlite(const FlatIndex& index, const std::string& path,
                  bool enable_expensive_checks = false);
}  // namespace indexer
}  // namespace oss_fuzz

#endif  // OSS_FUZZ_INFRA_INDEXER_INDEX_SQLITE_H_
