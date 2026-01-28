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

#include "indexer/frontend/pp_callbacks.h"

#include "indexer/frontend/common.h"
#include "indexer/index/types.h"
#include "clang/Basic/IdentifierTable.h"
#include "clang/Basic/SourceLocation.h"
#include "clang/Lex/MacroInfo.h"
#include "clang/Lex/PPCallbacks.h"
#include "llvm/ADT/StringRef.h"

namespace oss_fuzz {
namespace indexer {
LocationId PpCallbacks::GetLocationId(clang::SourceLocation start,
                                      clang::SourceLocation end) {
  return oss_fuzz::indexer::GetLocationId(index_, source_manager_,
                                          start, end);
}

EntityId PpCallbacks::GetEntityIdForMacro(llvm::StringRef name,
                                          const clang::MacroInfo* macro_info) {
  LocationId location_id = GetLocationId(macro_info->getDefinitionLoc(),
                                         macro_info->getDefinitionEndLoc());
  if (location_id == kInvalidLocationId) {
    return kInvalidEntityId;
  }
  return index_.GetEntityId({Entity::Kind::kMacro, "", name, "", location_id});
}

void PpCallbacks::MacroExpands(const clang::Token& name_token,
                               const clang::MacroDefinition& definition,
                               clang::SourceRange range,
                               const clang::MacroArgs* args) {
  llvm::StringRef name = name_token.getIdentifierInfo()->getName();
  const clang::MacroInfo* info = definition.getMacroInfo();
  LocationId location_id = GetLocationId(range.getBegin(), range.getEnd());
  EntityId entity_id = GetEntityIdForMacro(name, info);
  if (location_id != kInvalidLocationId && entity_id != kInvalidEntityId) {
    index_.GetReferenceId({entity_id, location_id});
  }
}

void PpCallbacks::MacroDefined(const clang::Token& name_token,
                               const clang::MacroDirective* directive) {
  llvm::StringRef name = name_token.getIdentifierInfo()->getName();
  const clang::MacroInfo* info = directive->getMacroInfo();
  GetEntityIdForMacro(name, info);
}
}  // namespace indexer
}  // namespace oss_fuzz
