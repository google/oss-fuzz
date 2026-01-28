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

#ifndef OSS_FUZZ_INFRA_INDEXER_FRONTEND_INDEX_ACTION_H_
#define OSS_FUZZ_INFRA_INDEXER_FRONTEND_INDEX_ACTION_H_

#include <memory>

#include "indexer/index/file_copier.h"
#include "indexer/index/in_memory_index.h"
#include "indexer/merge_queue.h"
#include "clang/AST/ASTConsumer.h"
#include "clang/Frontend/FrontendAction.h"
#include "clang/Frontend/Utils.h"
#include "clang/Tooling/Tooling.h"
#include "llvm/ADT/StringRef.h"

namespace oss_fuzz {
namespace indexer {
class AllDependenciesCollector : public clang::DependencyCollector {
 public:
  // Also include files from the "system" locations.
  bool needSystemDependencies() override { return true; }
};

// IndexAction provides the entry-point for the indexing tooling. This should
// typically not be used directly, and the functions exposed in
// indexer/frontend.h should be used instead.
class IndexAction : public clang::ASTFrontendAction {
 public:
  explicit IndexAction(FileCopier& file_copier, MergeQueue& merge_queue);

  bool BeginSourceFileAction(clang::CompilerInstance& compiler) override;
  void EndSourceFileAction() override;

  std::unique_ptr<clang::ASTConsumer> CreateASTConsumer(
      clang::CompilerInstance& compiler, llvm::StringRef) override;

 private:
  std::unique_ptr<InMemoryIndex> index_;
  MergeQueue& merge_queue_;
  std::unique_ptr<AllDependenciesCollector> dependencies_collector_;
};

class IndexActionFactory : public clang::tooling::FrontendActionFactory {
 public:
  explicit IndexActionFactory(FileCopier& file_copier, MergeQueue& merge_queue);

  std::unique_ptr<clang::FrontendAction> create() override;

 private:
  FileCopier& file_copier_;
  MergeQueue& merge_queue_;
};
}  // namespace indexer
}  // namespace oss_fuzz

#endif  // OSS_FUZZ_INFRA_INDEXER_FRONTEND_INDEX_ACTION_H_
