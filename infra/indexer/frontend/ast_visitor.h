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

#ifndef OSS_FUZZ_INFRA_INDEXER_FRONTEND_AST_VISITOR_H_
#define OSS_FUZZ_INFRA_INDEXER_FRONTEND_AST_VISITOR_H_

#include <optional>

#include "indexer/index/in_memory_index.h"
#include "indexer/index/types.h"
#include "absl/container/flat_hash_map.h"
#include "clang/AST/ASTConsumer.h"
#include "clang/AST/Decl.h"
#include "clang/AST/DeclTemplate.h"
#include "clang/AST/Expr.h"
#include "clang/AST/ExprCXX.h"
#include "clang/AST/RecursiveASTVisitor.h"
#include "clang/AST/Type.h"
#include "clang/Basic/SourceLocation.h"
#include "clang/Frontend/CompilerInstance.h"
#include "clang/Sema/Sema.h"

namespace oss_fuzz {
namespace indexer {
// AstVisitor handles the indexing operations for the AST. This should not be
// used directly, and the exposed api in indexer/frontend.h should be used
// instead.
class AstVisitor : public clang::RecursiveASTVisitor<AstVisitor> {
 public:
  AstVisitor(InMemoryIndex& index, clang::ASTContext& context,
             clang::CompilerInstance& compiler)
      : index_(index),
        context_(context),
        sema_(compiler.getSema()) {}

  bool shouldVisitImplicitCode() const { return true; }
  bool shouldVisitTemplateInstantiations() const { return true; }

  // clang::RecursiveASTVisitor<T> functions:
  // These are not overrides, since clang uses template magic to implement the
  // AST visitor instead of virtual function calls.
  bool VisitCallExpr(const clang::CallExpr *expr);
  bool VisitCXXConstructExpr(const clang::CXXConstructExpr *expr);
  bool VisitCXXNewExpr(const clang::CXXNewExpr *expr);
  bool VisitCXXDeleteExpr(const clang::CXXDeleteExpr *expr);
  bool VisitDeclRefExpr(const clang::DeclRefExpr *expr);
  bool VisitEnumDecl(const clang::EnumDecl *decl);
  bool VisitEnumConstantDecl(const clang::EnumConstantDecl *decl);
  bool VisitFieldDecl(const clang::FieldDecl *decl);
  bool VisitFunctionDecl(const clang::FunctionDecl *decl);
  bool VisitLambdaExpr(const clang::LambdaExpr *expr);
  bool VisitMemberExpr(const clang::MemberExpr *expr);
  bool VisitNonTypeTemplateParmDecl(const clang::NonTypeTemplateParmDecl *decl);
  bool VisitRecordDecl(clang::RecordDecl *decl);
  bool VisitTemplateTypeParmDecl(const clang::TemplateTypeParmDecl *decl);
  bool VisitTypedefNameDecl(const clang::TypedefNameDecl *decl);
  bool VisitUnaryExprOrTypeTraitExpr(
      const clang::UnaryExprOrTypeTraitExpr *expr);
  bool VisitVarDecl(const clang::VarDecl *decl);

 private:
  LocationId GetLocationId(clang::SourceLocation start,
                           clang::SourceLocation end);
  LocationId GetLocationId(const clang::Decl *decl);
  std::optional<Entity> GetEntityForDecl(
      const clang::Decl* decl, bool for_reference = false,
      LocationId location_id = kInvalidLocationId);
  EntityId GetEntityIdForDecl(const clang::Decl *decl,
                              bool for_reference = false);
  std::optional<SubstituteRelationship> GetTemplateSubstituteRelationship(
      const clang::Decl* template_decl, const clang::Decl* original_decl);
  void SynthesizeInheritedMemberEntities(
      const clang::CXXRecordDecl* class_decl);
  void AddSyntheticMemberReference(const clang::CXXRecordDecl* child_class,
                                   const clang::ValueDecl* inherited_member,
                                   const clang::SourceRange& range);
  void AddTypeReferencesFromLocation(LocationId location_id,
                                     const clang::Type *type,
                                     bool outermost_type = true);
  void AddReferencesForDecl(const clang::Decl *decl);
  void AddReferencesForExpr(const clang::Expr *expr);
  void AddDeclReferenceForSourceRange(const clang::SourceRange &range,
                                      const clang::Decl *decl);
  void AddTypeReferencesForSourceRange(const clang::SourceRange &range,
                                       const clang::Type *type);

  void AddVirtualMethodLinks(const clang::CXXMethodDecl* method_decl,
                             EntityId child_id);
  void AddSynthesizedVirtualMethodLinks(
      const clang::CXXMethodDecl* prototype_method_decl,
      const clang::CXXRecordDecl* child_class_decl, EntityId child_id);

  InMemoryIndex &index_;
  clang::ASTContext &context_;
  clang::Sema& sema_;

  struct CachedEntityId {
    EntityId entity_id;
    bool for_reference_only;
  };

  absl::flat_hash_map<const clang::Decl*, CachedEntityId> decl_to_entity_id_;
};
}  // namespace indexer
}  // namespace oss_fuzz

#endif  // OSS_FUZZ_INFRA_INDEXER_FRONTEND_AST_VISITOR_H_
