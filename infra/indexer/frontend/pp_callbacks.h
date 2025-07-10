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

#ifndef OSS_FUZZ_INFRA_INDEXER_FRONTEND_PP_CALLBACKS_H_
#define OSS_FUZZ_INFRA_INDEXER_FRONTEND_PP_CALLBACKS_H_

#include "indexer/index/in_memory_index.h"
#include "indexer/index/types.h"
#include "clang/Basic/SourceLocation.h"
#include "clang/Lex/MacroInfo.h"
#include "clang/Lex/PPCallbacks.h"
#include "llvm/ADT/StringRef.h"

namespace oss_fuzz {
namespace indexer {
// PpCallbacks indexes macro definitions and expansions.
class PpCallbacks : public clang::PPCallbacks {
 public:
  PpCallbacks(InMemoryIndex& index, clang::SourceManager& source_manager)
      : index_(index), source_manager_(source_manager) {}
  ~PpCallbacks() override = default;

  // clang::PPCallbacks functions:
  void MacroExpands(const clang::Token& name,
                    const clang::MacroDefinition& definition,
                    clang::SourceRange range,
                    const clang::MacroArgs* args) override;

  void MacroDefined(const clang::Token& name,
                    const clang::MacroDirective* directive) override;

 private:
  LocationId GetLocationId(clang::SourceLocation start,
                           clang::SourceLocation end);
  EntityId GetEntityIdForMacro(llvm::StringRef name,
                               const clang::MacroInfo* macro_info);

  InMemoryIndex& index_;
  clang::SourceManager& source_manager_;
};
}  // namespace indexer
}  // namespace oss_fuzz

#endif  // OSS_FUZZ_INFRA_INDEXER_FRONTEND_PP_CALLBACKS_H_
