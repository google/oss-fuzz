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

#include "indexer/frontend/index_action.h"

#include <memory>
#include <string>
#include <utility>
#include <vector>

#include "indexer/frontend/ast_visitor.h"
#include "indexer/frontend/common.h"
#include "indexer/frontend/pp_callbacks.h"
#include "indexer/index/file_copier.h"
#include "indexer/index/in_memory_index.h"
#include "indexer/index/types.h"
#include "indexer/merge_queue.h"
#include "absl/flags/flag.h"
#include "absl/log/check.h"
#include "absl/strings/match.h"
#include "absl/strings/string_view.h"
#include "clang/AST/ASTConsumer.h"
#include "clang/Frontend/CompilerInstance.h"
#include "clang/Frontend/Utils.h"
#include "clang/Lex/Pragma.h"
#include "clang/Lex/Preprocessor.h"
#include "llvm/ADT/StringRef.h"

ABSL_FLAG(std::vector<std::string>, ignore_pragmas, {},
          "#pragma(s) to ignore, comma-separated");

namespace oss_fuzz {
namespace indexer {
class AstConsumer : public clang::ASTConsumer {
 public:
  explicit AstConsumer(InMemoryIndex& index, clang::CompilerInstance& compiler)
      : index_(index), compiler_(compiler) {}
  ~AstConsumer() override = default;

  void HandleTranslationUnit(clang::ASTContext& context) override {
    AstVisitor visitor(index_, context, compiler_);
    visitor.TraverseDecl(context.getTranslationUnitDecl());
  }

 private:
  InMemoryIndex& index_;
  clang::CompilerInstance& compiler_;
};

IndexAction::IndexAction(FileCopier& file_copier, MergeQueue& merge_queue)
    : index_(std::make_unique<InMemoryIndex>(file_copier)),
      merge_queue_(merge_queue) {}

bool IndexAction::BeginSourceFileAction(clang::CompilerInstance& compiler) {
  CHECK(index_);

  dependencies_collector_ = std::make_unique<AllDependenciesCollector>();

  clang::Preprocessor& preprocessor = compiler.getPreprocessor();
  dependencies_collector_->attachToPreprocessor(preprocessor);
  preprocessor.addPPCallbacks(
      std::make_unique<PpCallbacks>(*index_, compiler.getSourceManager()));
  for (const std::string& ignored_pragma :
       absl::GetFlag(FLAGS_ignore_pragmas)) {
    preprocessor.AddPragmaHandler(
        new clang::EmptyPragmaHandler(ignored_pragma));
  }

  // TODO: b/409708640 - Support indexing assembly files.
  return !absl::EndsWith(compiler.getFrontendOpts().Inputs[0].getFile(), ".S");
}

void IndexAction::EndSourceFileAction() {
  const clang::SourceManager& source_manager =
      getCompilerInstance().getSourceManager();
  for (const std::string& filename :
       dependencies_collector_->getDependencies()) {
    if (!IsRealPath(filename)) {
      continue;
    }
    const auto absolute_path =
        ToNormalizedAbsolutePath(filename, source_manager);
    // Create a "whole file" location per filename to make sure files without
    // indexed symbols are still copied and e.g. accounted for in deltas.
    index_->GetLocationId(Location::WholeFile(absolute_path));
  }
  dependencies_collector_.reset();

  merge_queue_.Add(std::move(index_));
}

std::unique_ptr<clang::ASTConsumer> IndexAction::CreateASTConsumer(
    clang::CompilerInstance& compiler, llvm::StringRef path) {
  return std::make_unique<AstConsumer>(*index_, compiler);
}

IndexActionFactory::IndexActionFactory(FileCopier& file_copier,
                                       MergeQueue& merge_queue)
    : file_copier_(file_copier), merge_queue_(merge_queue) {}

std::unique_ptr<clang::FrontendAction> IndexActionFactory::create() {
  return std::make_unique<IndexAction>(file_copier_, merge_queue_);
}
}  // namespace indexer
}  // namespace oss_fuzz
