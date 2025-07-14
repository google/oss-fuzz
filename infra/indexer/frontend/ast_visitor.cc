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

#include "indexer/frontend/ast_visitor.h"

#include <cassert>
#include <list>
#include <optional>
#include <string>
#include <vector>

#include "indexer/frontend/common.h"
#include "indexer/index/types.h"
#include "absl/log/check.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/str_join.h"
#include "clang/AST/Attr.h"
#include "clang/AST/Decl.h"
#include "clang/AST/DeclCXX.h"
#include "clang/AST/DeclTemplate.h"
#include "clang/AST/DeclarationName.h"
#include "clang/AST/Expr.h"
#include "clang/AST/ExprCXX.h"
#include "clang/AST/PrettyPrinter.h"
#include "clang/AST/TemplateBase.h"
#include "clang/AST/Type.h"
#include "clang/Basic/FileEntry.h"
#include "clang/Basic/SourceLocation.h"
#include "clang/Basic/Specifiers.h"
#include "clang/Basic/TypeTraits.h"
#include "clang/Sema/Sema.h"
#include "llvm/ADT/APSInt.h"
#include "llvm/ADT/ArrayRef.h"
#include "llvm/ADT/SmallString.h"
#include "llvm/ADT/StringRef.h"
#include "llvm/Support/Casting.h"
#include "llvm/Support/raw_ostream.h"

namespace oss_fuzz {
namespace indexer {
namespace {

const clang::PrintingPolicy& GetPrintingPolicy() {
  static clang::PrintingPolicy policy({});
  policy.adjustForCPlusPlus();
  policy.SplitTemplateClosers = false;
  policy.SuppressTemplateArgsInCXXConstructors = true;
  return policy;
}

// Helper functions used to distinguish between declarations and definitions, so
// that we can mark declarations as incomplete and resolve them at a later
// stage.
bool IsADefinition(const clang::Decl* decl) {
  if (llvm::isa<clang::RecordDecl>(decl)) {
    const auto* record_decl = llvm::cast<clang::RecordDecl>(decl);
    if (!record_decl->isThisDeclarationADefinition() &&
        !llvm::isa<clang::ClassTemplateSpecializationDecl>(decl)) {
      return false;
    }
  } else if (llvm::isa<clang::FunctionDecl>(decl)) {
    const auto* function_decl = llvm::cast<clang::FunctionDecl>(decl);
    if (llvm::isa<clang::CXXMethodDecl>(function_decl)) {
      const auto* cxx_method_decl =
          llvm::cast<clang::CXXMethodDecl>(function_decl);
      if (cxx_method_decl->getParent()->isLambda()) {
        return true;
      }
    }
    if (!function_decl->isThisDeclarationADefinition()) {
      return false;
    }
  }
  return true;
}

bool IsParentADefinition(const clang::Decl* decl) {
  const auto* parent_context = decl->getNonTransparentDeclContext();
  if (llvm::isa<clang::Decl>(parent_context)) {
    const auto* parent = llvm::cast<clang::Decl>(parent_context);
    return IsADefinition(parent);
  } else {
    return true;
  }
}

const clang::ClassTemplateDecl* GetClassTemplateDefinition(
    const clang::ClassTemplateDecl* class_template_decl) {
  if (class_template_decl->getTemplatedDecl()->getDefinition()) {
    class_template_decl = class_template_decl->getTemplatedDecl()
                              ->getDefinition()
                              ->getDescribedClassTemplate();
  }
  return class_template_decl;
}

const clang::ClassTemplateSpecializationDecl* FindSpecialization(
    const clang::ClassTemplateDecl* class_template_decl,
    const llvm::ArrayRef<clang::TemplateArgument> args) {
  // XXX(kartynnik): `findSpecialization` is a non-`const` method because it can
  // lead to loading external specializations. Arguably this could have been
  // handled through `mutable` fields because logically this doesn't affect the
  // forthcoming behavior of the object.
  void* insert_pos = nullptr;
  return const_cast<clang::ClassTemplateDecl*>(class_template_decl)
      ->findSpecialization(args, insert_pos);
}

// Helper functions to find the closest explicit template specialization that
// matches the provided template arguments.
const clang::Decl* GetSpecializationDecl(
    const clang::ClassTemplateDecl* class_template_decl,
    const llvm::ArrayRef<clang::TemplateArgument> template_arguments) {
  class_template_decl = GetClassTemplateDefinition(class_template_decl);
  const clang::Decl* decl = class_template_decl;
  const auto* specialization_decl =
      FindSpecialization(class_template_decl, template_arguments);
  while (specialization_decl) {
    // This happens when we have a forward declaration of a template class,
    // followed by an explicit instantiation, followed by the definition. In
    // that case, when we look for the correct specialization of the template
    // class definition, we get a ClassTemplateSpecializationDecl which is of
    // type TSK_Undeclared and which references the forward declaration of the
    // template class instead of the correct definition. Calling
    // getInstantiatedFrom on such a ClassTemplateSpecializationDecl will return
    // null.
    //
    // FrontendTest.UsingSpecialization tests the handling of this case.
    if (specialization_decl->getSpecializationKind() ==
        clang::TemplateSpecializationKind::TSK_Undeclared) {
      return class_template_decl;
    }

    // Otherwise we should be able to continue walking the chain of
    // specialisations until we find the best match.
    const auto instantiated_from = specialization_decl->getInstantiatedFrom();
    if (instantiated_from.isNull()) {
      // Includes the case of `specialization_decl->isExplicitSpecialization()`.
      decl = specialization_decl;
      break;
    } else if (llvm::isa<clang::ClassTemplateDecl*>(instantiated_from)) {
      decl = llvm::cast<clang::ClassTemplateDecl*>(instantiated_from);
      break;
    } else {
      specialization_decl =
          llvm::cast<clang::ClassTemplatePartialSpecializationDecl*>(
              instantiated_from);
    }
  }

  if (llvm::isa<clang::ClassTemplateDecl>(decl)) {
    decl =
        GetClassTemplateDefinition(llvm::cast<clang::ClassTemplateDecl>(decl));
  }

  return decl;
}

const clang::Decl* GetSpecializationDecl(
    const clang::TemplateSpecializationType* type) {
  // There's no direct link to the clang::Type for the template type being
  // specialized, so this gets us a reference to the underlying template.
  //
  // Note that template_decl can be nullptr in the case of template template
  // parameters that are still instantiation dependent in this specialization.
  // Those are not "real" types, so we don't want to add references to them.
  const auto* template_decl = type->getTemplateName().getAsTemplateDecl();
  const clang::Decl* decl = template_decl;
  if (template_decl) {
    if (llvm::isa<clang::ClassTemplateDecl>(template_decl)) {
      auto* class_template_decl =
          llvm::cast<clang::ClassTemplateDecl>(template_decl);
      decl = GetSpecializationDecl(class_template_decl,
                                   type->template_arguments());
    } else if (llvm::isa<clang::TypeAliasTemplateDecl>(template_decl)) {
      return llvm::cast<clang::TypeAliasTemplateDecl>(template_decl)
          ->getTemplatedDecl();
    }
  }

  return decl;
}

const clang::Decl* GetSpecializationDecl(
    const clang::ClassTemplateSpecializationDecl* decl) {
  // If this is an explicit specialization, then there's no need to look for
  // the best matching specialization.
  if (decl->isExplicitSpecialization()) {
    return decl;
  }
  return GetSpecializationDecl(decl->getSpecializedTemplate(),
                               decl->getTemplateArgs().asArray());
}

const clang::CXXRecordDecl* GetCanonicalRecordDecl(
    const clang::ClassTemplateSpecializationDecl* decl) {
  const clang::Decl* specialization_decl = GetSpecializationDecl(decl);
  if (const auto* class_template_decl =
          llvm::dyn_cast<clang::ClassTemplateDecl>(specialization_decl)) {
    return class_template_decl->getTemplatedDecl();
  }
  const clang::CXXRecordDecl* record_decl =
      llvm::dyn_cast<clang::ClassTemplateSpecializationDecl>(
          specialization_decl);
  CHECK_NE(record_decl, nullptr);
  return record_decl;
}

bool IsIncompleteFunction(const clang::FunctionDecl* function_decl) {
  return !function_decl->hasBody() && !function_decl->isDefaulted() &&
         !function_decl->isPureVirtual() && !function_decl->getBuiltinID(true);
}

// Sometimes for a templated function in a class template, we would encounter
// a partial specialization like Class<int>::MyFunction<T>(). Notoriously,
// such functions don't refer back to the template they were instantiated from;
// moreover, they're safe to ignore because they're both incomplete and inline.
bool IsEphemeralContext(const clang::DeclContext* context) {
  const clang::FunctionDecl* function_decl =
      llvm::dyn_cast<clang::FunctionDecl>(context);
  if (function_decl == nullptr) {
    return false;
  }
  return IsIncompleteFunction(function_decl) && function_decl->isInlined();
}

// `decl` is required to be a `clang::NamedDecl`.
// If it is inside a template instantiation, finds the context where it is
// instantiated from and finds the corresponding entity by name.
const clang::NamedDecl* GetCanonicalNamedDecl(const clang::Decl* decl) {
  const clang::NamedDecl* named_decl = llvm::dyn_cast<clang::NamedDecl>(decl);
  CHECK_NE(named_decl, nullptr);
  if (named_decl->getName().empty()) {
    // Such as for a `DecompositionDecl`.
    return nullptr;
  }
  const clang::DeclContext* canonical_context = nullptr;

  if (const auto* class_specialization_decl =
          llvm::dyn_cast<clang::ClassTemplateSpecializationDecl>(
              named_decl->getDeclContext())) {
    if (class_specialization_decl->isExplicitSpecialization()) {
      return nullptr;
    }
    if (const clang::CXXRecordDecl* template_definition =
            GetCanonicalRecordDecl(class_specialization_decl)) {
      canonical_context = template_definition;
    } else {
      return nullptr;
    }
  } else if (const auto* function_decl = llvm::dyn_cast<clang::FunctionDecl>(
                 named_decl->getDeclContext())) {
    if (const clang::FunctionDecl* instantiation_pattern =
            function_decl->getTemplateInstantiationPattern()) {
      canonical_context = instantiation_pattern;
    } else {
      return nullptr;
    }
  } else {
    return nullptr;
  }

  clang::DeclarationName field_name = named_decl->getDeclName();
  // We are using `decls` instead of `fields` to also account for statics.
  for (const clang::Decl* inner_decl : canonical_context->decls()) {
    if (const auto* inner_named_decl =
            llvm::dyn_cast<clang::NamedDecl>(inner_decl)) {
      if (inner_named_decl->getDeclName() == field_name) {
        if (const auto* var_template_decl =
                llvm::dyn_cast<clang::VarTemplateDecl>(inner_named_decl)) {
          return var_template_decl->getTemplatedDecl();
        }
        if (llvm::isa<clang::BindingDecl>(inner_named_decl)) {
          // TODO: Figure out if we can support these.
          return nullptr;
        }
        return inner_named_decl;
      }
    }
  }
  return nullptr;
}

// Helper functions used to print template parameters for template declarations
// and specializations, since this code can be shared between class and function
// templates.
std::string FormatTemplateParameters(
    const clang::TemplateParameterList* params) {
  llvm::SmallString<128> string;
  llvm::raw_svector_ostream stream(string);
  stream << "<";
  for (int i = 0; i < params->size(); ++i) {
    if (i != 0) {
      stream << ", ";
    }
    const auto* param = params->getParam(i);
    if (llvm::isa<clang::NonTypeTemplateParmDecl>(param)) {
      const auto* value_param =
          llvm::cast<clang::NonTypeTemplateParmDecl>(param);
      auto value_type = value_param->getType();
      stream << value_type.getAsString(GetPrintingPolicy());
    } else {
      param->getNameForDiagnostic(stream, GetPrintingPolicy(), false);
      if (param->isParameterPack()) {
        stream << "...";
      }
    }
  }
  stream << ">";
  return stream.str().str();
}

std::string FormatTemplateArguments(
    const clang::TemplateParameterList* params,
    llvm::ArrayRef<clang::TemplateArgument> args) {
  llvm::SmallString<128> string;
  llvm::raw_svector_ostream stream(string);
  clang::printTemplateArgumentList(stream, args, GetPrintingPolicy(), params);
  return stream.str().str();
}

// Helper functions to generate the `<typename T, int S>` suffixes when handling
// templates.
std::string GetTemplateParameterSuffix(const clang::ClassTemplateDecl* decl) {
  return FormatTemplateParameters(decl->getTemplateParameters());
}

std::string GetTemplateParameterSuffix(
    const clang::ClassTemplateSpecializationDecl* decl) {
  llvm::SmallString<128> string;
  llvm::raw_svector_ostream stream(string);
  decl->getNameForDiagnostic(stream, GetPrintingPolicy(), false);
  return stream.str().str().substr(decl->getNameAsString().size());
}

std::string GetTemplateParameterSuffix(
    const clang::TypeAliasTemplateDecl* decl) {
  return FormatTemplateParameters(decl->getTemplateParameters());
}

std::string GetTemplateParameterSuffix(
    const clang::FunctionTemplateDecl* decl) {
  return FormatTemplateParameters(decl->getTemplateParameters());
}

std::string GetTemplateParameterSuffix(
    const clang::TemplateSpecializationType* type) {
  const auto* template_decl = type->getTemplateName().getAsTemplateDecl();
  if (llvm::isa<clang::ClassTemplateDecl>(template_decl)) {
    const auto* class_template_decl =
        llvm::cast<clang::ClassTemplateDecl>(template_decl);
    return GetTemplateParameterSuffix(
        FindSpecialization(class_template_decl, type->template_arguments()));
  } else {
    CHECK(llvm::isa<clang::TypeAliasTemplateDecl>(template_decl));
    const auto* type_alias_template_decl =
        llvm::cast<clang::TypeAliasTemplateDecl>(template_decl);
    return FormatTemplateArguments(
        type_alias_template_decl->getTemplateParameters(),
        type->template_arguments());
  }
}

std::string GetTemplateParameterSuffix(
    const clang::FunctionTemplateSpecializationInfo* info) {
  return FormatTemplateArguments(info->getTemplate()->getTemplateParameters(),
                                 info->TemplateArguments->asArray());
}

std::string GetName(const clang::Decl* decl) {
  std::string name = "";
  if (auto field_decl = llvm::dyn_cast<clang::FieldDecl>(decl);
      field_decl && field_decl->isAnonymousStructOrUnion()) {
    // Implicit unnamed fields for anonymous structs/unions are named after the
    // latter. We ignore them elsewhere; this is only for tests to assert
    // they're absent (the name contains the source file path otherwise).
    decl = field_decl->getType()->getAsRecordDecl();
    CHECK_NE(decl, nullptr);
  }
  if (llvm::isa<clang::RecordDecl>(decl)) {
    const auto* record_decl = llvm::cast<clang::RecordDecl>(decl);
    name = record_decl->getName().str();
    if (name.empty() && record_decl->isStruct()) {
      return "(anonymous struct)";
    } else if (name.empty() && record_decl->isUnion()) {
      return "(anonymous union)";
    }
  } else if (llvm::isa<clang::NamedDecl>(decl)) {
    // Lambda function handling is a little bit tricky, since we want to use
    // the implicit operator() definition, but that doesn't track whether we are
    // in a lambda function, so we need to check whether the parent decl is an
    // implicit lambda class.
    if (llvm::isa<clang::CXXMethodDecl>(decl)) {
      auto* cxx_method_decl = llvm::cast<clang::CXXMethodDecl>(decl);
      if (cxx_method_decl->getParent()->isLambda()) {
        return "lambda";
      }
    }
    const auto* named_decl = llvm::cast<clang::NamedDecl>(decl);
    llvm::SmallString<32> string;
    llvm::raw_svector_ostream stream(string);
    named_decl->printName(stream, GetPrintingPolicy());
    name = string.str().str();
  }

  return name;
}

std::string GetNameSuffix(const clang::Decl* decl) {
  std::string name_suffix = "";
  if (llvm::isa<clang::CXXRecordDecl>(decl)) {
    const auto* cxx_record_decl = llvm::cast<clang::CXXRecordDecl>(decl);
    if (llvm::isa<clang::ClassTemplateSpecializationDecl>(decl)) {
      const auto* class_template_specialization_decl =
          llvm::cast<clang::ClassTemplateSpecializationDecl>(decl);
      name_suffix =
          GetTemplateParameterSuffix(class_template_specialization_decl);
    } else if (cxx_record_decl->getDescribedClassTemplate()) {
      name_suffix = GetTemplateParameterSuffix(
          cxx_record_decl->getDescribedClassTemplate());
    }
  } else if (llvm::isa<clang::FunctionDecl>(decl)) {
    const auto* function_decl = llvm::cast<clang::FunctionDecl>(decl);

    std::string template_param_suffix = "";
    if (function_decl->getTemplateSpecializationInfo()) {
      template_param_suffix = GetTemplateParameterSuffix(
          function_decl->getTemplateSpecializationInfo());
    } else if (function_decl->getDescribedFunctionTemplate()) {
      template_param_suffix = GetTemplateParameterSuffix(
          function_decl->getDescribedFunctionTemplate());
    }

    std::vector<std::string> param_types;
    param_types.reserve(function_decl->getNumParams());
    for (int i = 0; i < function_decl->getNumParams(); ++i) {
      const clang::ParmVarDecl* parm_decl = function_decl->getParamDecl(i);
      param_types.emplace_back(
          parm_decl->getType().getAsString(GetPrintingPolicy()));
    }

    if (function_decl->isVariadic()) {
      param_types.emplace_back("...");
    }

    name_suffix = absl::StrCat(template_param_suffix, "(",
                               absl::StrJoin(param_types, ", "), ")");

    if (llvm::isa<clang::CXXMethodDecl>(decl)) {
      const auto* cxx_method_decl = llvm::cast<clang::CXXMethodDecl>(decl);
      if (!cxx_method_decl->getParent()->isLambda()) {
        if (cxx_method_decl->isConst()) {
          absl::StrAppend(&name_suffix, " const");
        }
        if (cxx_method_decl->isVolatile()) {
          absl::StrAppend(&name_suffix, " volatile");
        }
        switch (cxx_method_decl->getRefQualifier()) {
          case clang::RQ_None:
            break;
          case clang::RQ_LValue:
            absl::StrAppend(&name_suffix, " &");
            break;
          case clang::RQ_RValue:
            absl::StrAppend(&name_suffix, " &&");
            break;
        }
      }
    }
  } else if (llvm::isa<clang::TypeAliasDecl>(decl)) {
    const auto* type_alias_decl = llvm::cast<clang::TypeAliasDecl>(decl);
    const auto* type_alias_template_decl =
        type_alias_decl->getDescribedAliasTemplate();
    if (type_alias_template_decl) {
      name_suffix = GetTemplateParameterSuffix(type_alias_template_decl);
    }
  }

  return name_suffix;
}

std::string GetNamePrefix(const clang::Decl* decl) {
  if (llvm::isa<clang::ParmVarDecl>(decl)) {
    return {};
  }

  std::list<std::string> parts = {""};

  // Function names should only appear in the name prefix in specific cases.
  //
  // 1. Declaration of a template parameter for a function or member function
  //    template:
  //    ```
  //    template <typename T>
  //    void foo(T bar);
  //    ```
  //    In this case, the Type entity for `T` should be qualified as
  //    `foo<typename T>()::T`
  //
  // 2. Declaration of a nested type/class/enum or a nested function:
  //    ```
  //    int foo() {
  //      class Bar {
  //      };
  //    }
  //    ```
  //    In this case, the Class entity for `Bar` should be qualified as
  //    `foo()::Bar`
  //
  // Technically, I think the return type should be included when functions are
  // used as qualifiers, but since return type overloading is not allowed I
  // don't think that this is necessary, so it is omitted at present.
  //
  // In practice this means that we want to include functions in fully qualified
  // names for anything other than variable declarations.
  bool include_function_scope = !llvm::isa<clang::VarDecl>(decl);
  const auto* decl_context = decl->getNonTransparentDeclContext();
  while (decl_context) {
    if (llvm::isa<clang::FunctionDecl>(decl_context)) {
      if (!include_function_scope) {
        // If we're not including function scopes, then we can stop when we
        // reach the first containing function.
        break;
      }

      const auto* parent_decl = llvm::cast<clang::Decl>(decl_context);
      parts.push_front(
          absl::StrCat(GetName(parent_decl), GetNameSuffix(parent_decl)));
    } else if (llvm::isa<clang::NamespaceDecl>(decl_context)) {
      // namespace name should always appear in our name prefix.
      const auto* namespace_decl =
          llvm::cast<clang::NamespaceDecl>(decl_context);
      if (namespace_decl->isAnonymousNamespace()) {
        parts.push_front("(anonymous namespace)");
      } else {
        parts.push_front(namespace_decl->getName().str());
      }
    } else if (llvm::isa<clang::RecordDecl>(decl_context)) {
      bool is_lambda = false;
      if (llvm::isa<clang::CXXRecordDecl>(decl_context)) {
        const auto* cxx_record_decl =
            llvm::cast<clang::CXXRecordDecl>(decl_context);
        is_lambda = cxx_record_decl->isLambda();
      }
      // class / union / struct name should always appear in our name prefix,
      // unless it's the implicit class for a lambda function.
      if (!is_lambda) {
        const auto* parent_decl = llvm::cast<clang::Decl>(decl_context);
        parts.push_front(
            absl::StrCat(GetName(parent_decl), GetNameSuffix(parent_decl)));
      }
    } else if (llvm::isa<clang::EnumDecl>(decl_context)) {
      const auto* enum_decl = llvm::cast<clang::EnumDecl>(decl_context);
      // The only time that an enum should appear in our name prefix is when it
      // is a c++11 scoped enum / enum class.
      if (enum_decl->isScoped() || enum_decl->isScopedUsingClassTag()) {
        const auto* parent_decl = llvm::cast<clang::Decl>(decl_context);
        parts.push_front(
            absl::StrCat(GetName(parent_decl), GetNameSuffix(parent_decl)));
      }
    }
    decl_context = decl_context->getParent();
  }

  return absl::StrJoin(parts, "::");
}

bool IsIgnoredImplicitDecl(const clang::Decl* decl) {
  // Don't index unreferenced implicit entities except implicit methods.
  // (We opt to declare all the implicit methods with a preference to report
  // e.g. an "implicitly defined" destructor over reporting it missing.)
  return decl->isImplicit() && !llvm::isa<clang::CXXMethodDecl>(decl);
}

void ReportTranslationUnit(llvm::raw_string_ostream& stream,
                           const clang::ASTContext& context) {
  const clang::SourceManager& source_manager = context.getSourceManager();
  clang::FileID main_file_id = source_manager.getMainFileID();
  const clang::FileEntry* main_file_entry =
      source_manager.getFileEntryForID(main_file_id);
  if (main_file_entry) {
    llvm::StringRef main_file_path = main_file_entry->tryGetRealPathName();
    stream << "Translation unit: '" << main_file_path << "'\n";
  }
}

std::string GetEnumValue(const clang::EnumConstantDecl* decl) {
  const llvm::APSInt& value = decl->getInitVal();
  std::string string_value;
  llvm::raw_string_ostream stream(string_value);
  stream << value;
  return string_value;
}

}  // namespace

bool AstVisitor::VisitCallExpr(const clang::CallExpr* expr) {
  AddReferencesForExpr(expr);
  return true;
}

bool AstVisitor::VisitCXXConstructExpr(const clang::CXXConstructExpr* expr) {
  AddReferencesForExpr(expr);
  return true;
}

bool AstVisitor::VisitCXXDeleteExpr(const clang::CXXDeleteExpr* expr) {
  AddReferencesForExpr(expr);
  return true;
}

bool AstVisitor::VisitCXXNewExpr(const clang::CXXNewExpr* expr) {
  AddReferencesForExpr(expr);
  return true;
}

bool AstVisitor::VisitDeclRefExpr(const clang::DeclRefExpr* expr) {
  AddReferencesForExpr(expr);
  return true;
}

bool AstVisitor::VisitEnumDecl(const clang::EnumDecl* decl) {
  GetEntityIdForDecl(decl);
  return true;
}

bool AstVisitor::VisitEnumConstantDecl(const clang::EnumConstantDecl* decl) {
  GetEntityIdForDecl(decl);
  return true;
}

bool AstVisitor::VisitFieldDecl(const clang::FieldDecl* decl) {
  GetEntityIdForDecl(decl);
  AddReferencesForDecl(decl);
  return true;
}

bool AstVisitor::VisitFunctionDecl(const clang::FunctionDecl* decl) {
  // We only need to add an entity for a FunctionDecl that is the definition,
  // or if there is no definition in this translation unit, and we never add an
  // entity for a deleted function.
  if (decl->isDeleted()) {
    return true;
  }
  if (IsADefinition(decl) || !decl->getDefinition()) {
    GetEntityIdForDecl(decl);
    AddReferencesForDecl(decl);
  }
  return true;
}

bool AstVisitor::VisitLambdaExpr(const clang::LambdaExpr* expr) {
  GetEntityIdForDecl(expr->getCallOperator());
  return true;
}

bool AstVisitor::VisitMemberExpr(const clang::MemberExpr* expr) {
  AddReferencesForExpr(expr);
  return true;
}

bool AstVisitor::VisitNonTypeTemplateParmDecl(
    const clang::NonTypeTemplateParmDecl* decl) {
  if (IsParentADefinition(decl)) {
    GetEntityIdForDecl(decl);
  }
  return true;
}

bool AstVisitor::VisitRecordDecl(clang::RecordDecl* decl) {
  if (decl->isInjectedClassName()) {
    // struct C {
    //   // C is implicitly declared here as a synonym for the class name.
    // };
    // C::C c; // same as "C c;"
    // Only index `C` in this case, and don't index `C::C`.
    return true;
  }

  if (auto* record_decl = llvm::dyn_cast<clang::CXXRecordDecl>(decl)) {
    // We opt to declare all the implicit members with a preference to report
    // e.g. an "implicitly defined" destructor over reporting it missing.
    compiler_.getSema().ForceDeclarationOfImplicitMembers(record_decl);
  }

  // As for FunctionDecl, we only need to add an entity for a RecordDecl if this
  // is the definition, or if there is no definition in this translation unit.
  if (IsADefinition(decl) || !decl->getDefinition()) {
    GetEntityIdForDecl(decl);
    AddReferencesForDecl(decl);
  }
  return true;
}

bool AstVisitor::VisitTemplateTypeParmDecl(
    const clang::TemplateTypeParmDecl* decl) {
  if (IsParentADefinition(decl)) {
    GetEntityIdForDecl(decl);
  }
  return true;
}

bool AstVisitor::VisitTypedefNameDecl(const clang::TypedefNameDecl* decl) {
  GetEntityIdForDecl(decl);
  AddReferencesForDecl(decl);
  return true;
}

bool AstVisitor::VisitUnaryExprOrTypeTraitExpr(
    const clang::UnaryExprOrTypeTraitExpr* expr) {
  // This is handling for the special kind of expression
  // size_t foo_size = sizeof(struct Foo);
  if ((expr->getKind() == clang::UETT_SizeOf ||
       expr->getKind() == clang::UETT_AlignOf) &&
      expr->isArgumentType()) {
    const auto* arg_type = expr->getArgumentType().getTypePtrOrNull();
    if (arg_type) {
      AddTypeReferencesForSourceRange(expr->getSourceRange(), arg_type);
    }
  }
  return true;
}

bool AstVisitor::VisitVarDecl(const clang::VarDecl* decl) {
  if (IsParentADefinition(decl)) {
    GetEntityIdForDecl(decl);
  }
  AddReferencesForDecl(decl);
  return true;
}

LocationId AstVisitor::GetLocationId(clang::SourceLocation start,
                                     clang::SourceLocation end) {
  return oss_fuzz::indexer::GetLocationId(index_, context_.getSourceManager(),
                                          start, end);
}

LocationId AstVisitor::GetLocationId(const clang::Decl* decl) {
  // If we have a template specialization or instantiation, we should make
  // sure we use the source location that matches the closest explicit
  // specialization instead of the base template.
  if (llvm::isa<clang::ClassTemplateSpecializationDecl>(decl)) {
    const auto* specialization_decl =
        llvm::cast<clang::ClassTemplateSpecializationDecl>(decl);
    decl = GetSpecializationDecl(specialization_decl);
  }

  // For class template definitions, the AST has two nodes:
  // - ClassTemplateDecl `template <typename T>`
  //   - CXXRecordDecl   `class Foo { ... };`
  // So, if we have a `CXXRecordDecl`, then we should check if we have an
  // associated class template, and use the outer location to give the full
  // definition.
  if (llvm::isa<clang::CXXRecordDecl>(decl)) {
    const auto* cxx_record_decl = llvm::cast<clang::CXXRecordDecl>(decl);
    if (cxx_record_decl->getDefinition()) {
      cxx_record_decl = cxx_record_decl->getDefinition();
    }

    const auto* class_template_decl =
        cxx_record_decl->getDescribedClassTemplate();
    if (class_template_decl) {
      decl = GetClassTemplateDefinition(class_template_decl);
    }
  }

  // For function template definitions, the AST also has two nodes:
  // - FunctionTemplateDecl `template <typename T>`
  //   - FunctionDecl       `void Foo(T bar) { ... }`
  // So we similarly need to check whether we have an associated function
  // template. However, for instantiation of function templates, we have an
  // extra level of indirection via `FunctionTemplateSpecializationInfo`.
  if (llvm::isa<clang::FunctionDecl>(decl)) {
    const auto* tmp = llvm::cast<clang::FunctionDecl>(decl);
    if (tmp->isTemplateInstantiation()) {
      tmp = tmp->getTemplateInstantiationPattern();
    } else if (tmp->getTemplateSpecializationInfo()) {
      const auto* tmp_info = tmp->getTemplateSpecializationInfo();
      tmp = tmp_info->getFunction();
    }

    decl = tmp;
    const auto* tmp_template = tmp->getDescribedFunctionTemplate();
    if (tmp_template) {
      return GetLocationId(tmp_template->getBeginLoc(),
                           tmp_template->getEndLoc());
    }
  }

  // If we reach here then we have updated decl to point to the correct location
  // already.
  return GetLocationId(decl->getBeginLoc(), decl->getEndLoc());
}

std::optional<EntityId> AstVisitor::GetEntityIdForCanonicalDecl(
    const clang::Decl* canonical_decl, const clang::Decl* original_decl) {
  if (canonical_decl == nullptr) {
    return std::nullopt;
  }
  const EntityId canonical_entity_id = GetEntityIdForDecl(canonical_decl);
  if (canonical_entity_id == kInvalidEntityId) {
    std::string str;
    llvm::raw_string_ostream stream(str);
    stream << "Please report an indexer issue marked 'CANONICAL':\n";
    ReportTranslationUnit(stream, context_);
    stream << "Original Decl:\n";
    original_decl->dump(stream);
    stream << "Canonical Decl:\n";
    canonical_decl->dump(stream);
    llvm::errs() << str;
    return std::nullopt;
  }
  return canonical_entity_id;
}

EntityId AstVisitor::GetEntityIdForDecl(const clang::Decl* decl,
                                        LocationId location_id,
                                        bool for_reference) {
  CHECK_NE(decl, nullptr);
  if (IsEphemeralContext(decl->getDeclContext())) {
    return kInvalidEntityId;
  }

  // Unless they are referenced, do not index `IsIgnoredImplicitDecl` subjects.
  if (!for_reference && IsIgnoredImplicitDecl(decl)) {
    return kInvalidEntityId;
  }

  // First handle assignments of lambda types, as we need to get the entity for
  // the lambda::operator() rather than the implicit invisible lambda class.
  if (llvm::isa<clang::CXXRecordDecl>(decl)) {
    auto* tmp = llvm::cast<clang::CXXRecordDecl>(decl);
    if (tmp->isLambda()) {
      return GetEntityIdForDecl(tmp->getLambdaCallOperator(), location_id);
    }
  }

  // Similarly, for ClassTemplateDecl we want the underlying CXXRecordDecl and
  // not the template wrapper decl.
  if (llvm::isa<clang::ClassTemplateDecl>(decl)) {
    const auto* class_template_decl =
        llvm::cast<clang::ClassTemplateDecl>(decl);
    decl = class_template_decl->getTemplatedDecl();
  }

  // Then handle structuring assignment.
  if (llvm::isa<clang::BindingDecl>(decl)) {
    auto* tmp = llvm::cast<clang::BindingDecl>(decl);
    decl = tmp->getHoldingVar();
    // It's possible that we don't have a holding var here.
    if (!decl) {
      return kInvalidEntityId;
    }
  }

  // Then resolve from the declaration to the definition of the entity.
  if (llvm::isa<clang::VarDecl>(decl)) {
    auto* tmp = llvm::cast<clang::VarDecl>(decl);
    if (!tmp->isThisDeclarationADefinition() && tmp->getDefinition()) {
      decl = tmp->getDefinition();
    }
  } else if (llvm::isa<clang::TagDecl>(decl)) {
    auto* tmp = llvm::cast<clang::TagDecl>(decl);
    if (!tmp->isThisDeclarationADefinition() && tmp->getDefinition()) {
      decl = tmp->getDefinition();
    }
  } else if (llvm::isa<clang::FunctionDecl>(decl)) {
    auto* tmp = llvm::cast<clang::FunctionDecl>(decl);
    if (!tmp->isThisDeclarationADefinition() && tmp->getDefinition()) {
      decl = tmp->getDefinition();
    }
  }

  // Defer getting the location in case the entity is invalid.
  auto get_location_id = [&]() {
    return location_id == kInvalidLocationId ? GetLocationId(decl)
                                             : location_id;
  };

  std::string name_prefix = GetNamePrefix(decl);
  std::string name = GetName(decl);
  std::string name_suffix = GetNameSuffix(decl);
  if (name.empty()) {
    return kInvalidEntityId;
  }

  if (llvm::isa<clang::VarDecl>(decl) || llvm::isa<clang::FieldDecl>(decl) ||
      llvm::isa<clang::NonTypeTemplateParmDecl>(decl)) {
    if (decl->isImplicit() || llvm::isa<clang::DecompositionDecl>(decl)) {
      // Implicit `VarDecl`s encountered were range `for` loop variables;
      // implicit `FieldDecl`s were unnamed anonymous struct/union fields
      // (see `FieldDecl::isAnonymousStructOrUnion`).
      // `DecompositionDecl` is unnamed but inherits from `VarDecl`.
      return kInvalidEntityId;
    }
    std::optional<EntityId> canonical_entity_id;
    if (llvm::isa<clang::FieldDecl>(decl) || llvm::isa<clang::VarDecl>(decl)) {
      canonical_entity_id =
          GetEntityIdForCanonicalDecl(GetCanonicalNamedDecl(decl), decl);
    }
    return index_.GetEntityId({Entity::Kind::kVariable, name_prefix, name,
                               name_suffix, get_location_id(),
                               /*is_incomplete=*/false, /*is_weak=*/false,
                               canonical_entity_id});
  } else if (llvm::isa<clang::RecordDecl>(decl)) {
    const auto* record_decl = llvm::cast<clang::RecordDecl>(decl);
    bool is_incomplete = !record_decl->getDefinition();
    std::optional<EntityId> canonical_entity_id;
    if (llvm::isa<clang::ClassTemplateSpecializationDecl>(decl)) {
      auto* class_template_specialization_decl =
          llvm::cast<clang::ClassTemplateSpecializationDecl>(decl);
      // All explicit specializations should be considered complete, as they
      // will be the definition that is used (when the specialization matches).
      if (class_template_specialization_decl->isExplicitSpecialization()) {
        is_incomplete = false;
      } else {
        // Otherwise, a template instantiation is complete iff the base class
        // being templated from is complete.
        const auto* class_template_decl =
            class_template_specialization_decl->getSpecializedTemplate();

        is_incomplete =
            !class_template_decl->getTemplatedDecl()->getDefinition();

        canonical_entity_id = GetEntityIdForCanonicalDecl(
            GetCanonicalRecordDecl(class_template_specialization_decl),
            class_template_specialization_decl);
      }
    }
    return index_.GetEntityId({Entity::Kind::kClass, name_prefix, name,
                               name_suffix, get_location_id(), is_incomplete,
                               /*is_weak=*/false, canonical_entity_id});
  } else if (llvm::isa<clang::EnumDecl>(decl)) {
    std::optional<EntityId> canonical_entity_id =
        GetEntityIdForCanonicalDecl(GetCanonicalNamedDecl(decl), decl);
    return index_.GetEntityId(
        {Entity::Kind::kEnum, name_prefix, name, name_suffix, get_location_id(),
         /*is_incomplete=*/false, /*is_weak=*/false, canonical_entity_id});
  } else if (llvm::isa<clang::EnumConstantDecl>(decl)) {
    const auto* enum_constant_decl = llvm::cast<clang::EnumConstantDecl>(decl);
    std::optional<EntityId> canonical_entity_id =
        GetEntityIdForCanonicalDecl(GetCanonicalNamedDecl(decl), decl);
    return index_.GetEntityId({Entity::Kind::kEnumConstant, name_prefix, name,
                               name_suffix, get_location_id(),
                               /*is_incomplete=*/false, /*is_weak=*/false,
                               canonical_entity_id,
                               /*implicitly_defined_for_entity_id=*/
                               std::nullopt,
                               /*enum_value=*/
                               GetEnumValue(enum_constant_decl)});
  } else if (llvm::isa<clang::TemplateTypeParmDecl>(decl) ||
             llvm::isa<clang::TypedefNameDecl>(decl)) {
    return index_.GetEntityId({Entity::Kind::kType, name_prefix, name,
                               name_suffix, get_location_id()});
  } else if (llvm::isa<clang::FunctionDecl>(decl)) {
    const auto* function_decl = llvm::cast<clang::FunctionDecl>(decl);
    bool is_incomplete = IsIncompleteFunction(function_decl);
    if (is_incomplete && function_decl->isInlined()) {
      // See the discussion for `IsEphemeralContext`.
      return kInvalidEntityId;
    }
    bool is_weak = !is_incomplete && function_decl->hasAttr<clang::WeakAttr>();

    // Note: Implicit methods are generally defined after template
    // instantiation, but an implicit comparison operator coming from (C++20)
    //   constexpr operator<=>(const TemplatedClass<T>& other);
    // can be instantiated by class template instantiations.
    // In this case we report the instantiation via `canonical_entity_id` which
    // refers to an implicit method in the template
    // (`implicitly_defined_for_entity_id`).
    //
    // In contrast, an implicit destructor of an (implicit) template
    // instantiation will have `implicitly_defined_for_entity_id` which in turn
    // has a 'canonical_entity_id`.
    std::optional<EntityId> canonical_entity_id = std::nullopt;
    std::optional<EntityId> implicitly_defined_for_entity_id = std::nullopt;
    if (function_decl->getTemplateInstantiationPattern()) {
      canonical_entity_id = GetEntityIdForCanonicalDecl(
          function_decl->getTemplateInstantiationPattern(), decl);
    } else if (function_decl->isImplicit() &&
               llvm::isa<clang::CXXMethodDecl>(function_decl)) {
      auto parent_class =
          llvm::cast<clang::CXXMethodDecl>(function_decl)->getParent();
      if (parent_class->getName().empty()) {
        // An anonymous struct's/union's implicit method; ignore.
        return kInvalidEntityId;
      }
      implicitly_defined_for_entity_id = GetEntityIdForDecl(parent_class);
      if (*implicitly_defined_for_entity_id == kInvalidEntityId) {
        // Case in point: Implicitly defined `struct __va_list_tag`.
        return kInvalidEntityId;
      }
    }
    return index_.GetEntityId({Entity::Kind::kFunction, name_prefix, name,
                               name_suffix, get_location_id(), is_incomplete,
                               is_weak, canonical_entity_id,
                               implicitly_defined_for_entity_id});
  }

  return kInvalidEntityId;
}

void AstVisitor::AddTypeReferencesFromLocation(LocationId location_id,
                                               const clang::Type* type,
                                               bool outermost_type) {
  const clang::Decl* type_decl = nullptr;

  // We can't add references if the location is invalid.
  if (location_id == kInvalidLocationId) return;

  // First strip indirections
  while (type->isPointerType() || type->isReferenceType()) {
    const auto* pointee_type = type->getPointeeOrArrayElementType();
    if (pointee_type == type) {
      break;
    }

    type = pointee_type;
  }

  // Then strip sugar (`struct` keyword, name qualifications, etc.)
  while (llvm::isa<clang::ElaboratedType>(type)) {
    const auto* elaborated_type = llvm::cast<clang::ElaboratedType>(type);
    type = elaborated_type->desugar().getTypePtrOrNull();
  }

  if (llvm::isa<clang::TemplateSpecializationType>(type)) {
    auto* specialization_type =
        llvm::cast<clang::TemplateSpecializationType>(type);
    // We need to add references to the parameter types in the case of a
    // template specialization. We only do this in the first level of recursion,
    // so that we don't get too noisy with the cross-references.
    if (outermost_type) {
      for (const auto& template_argument :
           specialization_type->template_arguments()) {
        if (template_argument.getKind() ==
            clang::TemplateArgument::ArgKind::Type) {
          const auto* argument_type =
              template_argument.getAsType().getTypePtrOrNull();
          if (argument_type) {
            AddTypeReferencesFromLocation(location_id, argument_type,
                                          /*outermost_type=*/false);
          }
        }
      }
    }

    // We want to add a reference to the "best matching" underlying template.
    // This should be the source code entity that closest matches the template
    // parameters; so the source code version of the template that will be
    // instantiated for this type.
    const auto* specialization_decl =
        GetSpecializationDecl(specialization_type);
    if (specialization_decl) {
      auto entity_id = GetEntityIdForDecl(specialization_decl,
                                          /*location_id=*/kInvalidLocationId,
                                          /*for_reference=*/true);
      if (entity_id != kInvalidEntityId) {
        (void)index_.GetReferenceId({entity_id, location_id});
      }
    }

    const auto* template_decl =
        specialization_type->getTemplateName().getAsTemplateDecl();
    LocationId decl_location_id = kInvalidLocationId;
    if (specialization_decl) {
      decl_location_id = GetLocationId(specialization_decl);
    } else if (template_decl) {
      decl_location_id = GetLocationId(template_decl);
    }

    // We need to manually create the entities for template specializations,
    // because when we have partial specializations or forward declarations,
    // we need a different source location than the one associated to the
    // canonical ClassTemplateDecl, and for partial specializations we also
    // need to override the name_suffix generation with information that is only
    // stored in the TemplateSpecializationType.
    if (decl_location_id != kInvalidLocationId) {
      if (template_decl &&
          llvm::isa<clang::TypeAliasTemplateDecl>(template_decl)) {
        std::string name_prefix = GetNamePrefix(template_decl);
        std::string name = GetName(template_decl);
        std::string name_suffix =
            GetTemplateParameterSuffix(specialization_type);

        auto* alias_template_decl =
            llvm::cast<clang::TypeAliasTemplateDecl>(template_decl);
        auto entity_id = index_.GetEntityId(
            {Entity::Kind::kType, name_prefix, name, name_suffix,
             decl_location_id,
             /*is_incomplete=*/false, /*is_weak=*/false,
             /*canonical_entity_id=*/
             GetEntityIdForDecl(alias_template_decl->getTemplatedDecl(),
                                /*location_id=*/kInvalidLocationId,
                                /*for_reference=*/true)});
        if (entity_id != kInvalidEntityId) {
          (void)index_.GetReferenceId({entity_id, location_id});
        }
      }
    }

    // Type declaration becomes the instantiation of the underlying template.
    type_decl = type->getAsTagDecl();
    if (type_decl) {
      auto entity_id =
          GetEntityIdForDecl(type_decl, /*location_id=*/kInvalidLocationId,
                             /*for_reference=*/true);
      if (entity_id != kInvalidEntityId) {
        (void)index_.GetReferenceId({entity_id, location_id});
      }
    }
  } else {
    if (llvm::isa<clang::TemplateTypeParmType>(type)) {
      type_decl = llvm::cast<clang::TemplateTypeParmType>(type)->getDecl();
    } else if (type->isTypedefNameType()) {
      // We need to add references to the inner-types in the case of typedefs.
      const clang::TypedefType* typedef_type_ptr =
          type->getAs<clang::TypedefType>();
      if (typedef_type_ptr) {
        const auto* typedef_decl = typedef_type_ptr->getDecl();
        const auto* underlying_type_ptr =
            typedef_decl->getUnderlyingType().getTypePtrOrNull();
        if (underlying_type_ptr) {
          AddTypeReferencesFromLocation(location_id, underlying_type_ptr,
                                        /*outermost_type=*/false);
        }

        type_decl = typedef_decl;
      }
    } else {
      type_decl = type->getAsTagDecl();
    }

    if (type_decl) {
      auto entity_id =
          GetEntityIdForDecl(type_decl, /*location_id=*/kInvalidLocationId,
                             /*for_reference=*/true);

      if (entity_id != kInvalidEntityId) {
        (void)index_.GetReferenceId({entity_id, location_id});
      }
    }
  }
}

void AstVisitor::AddReferencesForDecl(const clang::Decl* decl) {
  clang::SourceRange range = decl->getSourceRange();
  const clang::Type* type_ptr = nullptr;
  if (llvm::isa<clang::TypedefNameDecl>(decl)) {
    const auto* typedef_decl = llvm::cast<clang::TypedefNameDecl>(decl);
    type_ptr = typedef_decl->getUnderlyingType().getTypePtrOrNull();
  } else if (llvm::isa<clang::FunctionDecl>(decl)) {
    const auto* function_decl = llvm::cast<clang::FunctionDecl>(decl);
    type_ptr = function_decl->getReturnType().getTypePtrOrNull();
    // We truncate function return type type references to reference only the
    // function declaration/definition and not to include the lines for the
    // function body.
    if (function_decl->hasBody()) {
      range.setEnd(function_decl->getBody()->getSourceRange().getBegin());
    }
  } else if (llvm::isa<clang::CXXRecordDecl>(decl)) {
    const auto* cxx_record_decl = llvm::cast<clang::CXXRecordDecl>(decl);
    if (cxx_record_decl->isThisDeclarationADefinition()) {
      // C++ class definitions may have multiple inheritance, so we need to add
      // references to all base classes here.
      for (const auto& base : cxx_record_decl->bases()) {
        const auto* base_type_ptr = base.getType().getTypePtrOrNull();
        if (base_type_ptr) {
          AddTypeReferencesForSourceRange(range, base_type_ptr);
        }
      }
    }
  } else if (llvm::isa<clang::ValueDecl>(decl)) {
    const auto* value_decl = llvm::cast<clang::ValueDecl>(decl);
    type_ptr = value_decl->getType().getTypePtrOrNull();
  }

  if (type_ptr) {
    AddTypeReferencesForSourceRange(range, type_ptr);
  }
}

void AstVisitor::AddReferencesForExpr(const clang::Expr* expr) {
  const clang::Decl* decl = nullptr;
  if (llvm::isa<clang::CXXDeleteExpr>(expr)) {
    decl = llvm::cast<clang::CXXDeleteExpr>(expr)->getOperatorDelete();
  } else if (llvm::isa<clang::CXXNewExpr>(expr)) {
    decl = llvm::cast<clang::CXXNewExpr>(expr)->getOperatorNew();
  } else if (llvm::isa<clang::CallExpr>(expr)) {
    decl = llvm::cast<clang::CallExpr>(expr)->getCalleeDecl();
    if (decl && llvm::isa<clang::CXXMethodDecl>(decl)) {
      const auto* method_decl = llvm::cast<clang::CXXMethodDecl>(decl);
      if (method_decl->getParent()) {
        const auto* type = method_decl->getParent()->getTypeForDecl();
        if (type) {
          AddTypeReferencesForSourceRange(expr->getSourceRange(), type);
        }
      }
    }
  } else if (llvm::isa<clang::CXXConstructExpr>(expr)) {
    // Perhaps surprisingly, `CXXConstructExpr` is not a `CallExpr`.
    decl = llvm::cast<clang::CXXConstructExpr>(expr)->getConstructor();
    if (decl && llvm::isa<clang::CXXConstructorDecl>(decl)) {
      const auto* constructor_decl =
          llvm::cast<clang::CXXConstructorDecl>(decl);
      if (constructor_decl->getParent()) {
        const auto* type = constructor_decl->getParent()->getTypeForDecl();
        if (type) {
          AddTypeReferencesForSourceRange(expr->getSourceRange(), type);
        }
      }
    }
  } else if (llvm::isa<clang::DeclRefExpr>(expr)) {
    decl = llvm::cast<clang::DeclRefExpr>(expr)->getDecl();
  } else if (llvm::isa<clang::MemberExpr>(expr)) {
    const auto* member_expr = llvm::cast<clang::MemberExpr>(expr);
    decl = member_expr->getMemberDecl();
    if (member_expr->getBase()) {
      AddReferencesForExpr(member_expr->getBase());
    }
  } else if (llvm::isa<clang::LambdaExpr>(expr)) {
    decl = llvm::cast<clang::LambdaExpr>(expr)
               ->getLambdaClass()
               ->getLambdaCallOperator();
  }

  if (decl) {
    auto entity_id = GetEntityIdForDecl(
        decl, /*location_id=*/kInvalidLocationId, /*for_reference=*/true);
    auto location_id = GetLocationId(expr->getBeginLoc(), expr->getEndLoc());

    if (entity_id != kInvalidEntityId && location_id != kInvalidLocationId) {
      (void)index_.GetReferenceId({entity_id, location_id});
    }
  }
}

void AstVisitor::AddTypeReferencesForSourceRange(
    const clang::SourceRange& range, const clang::Type* type) {
  if (range.isInvalid()) {
    return;
  }
  auto location_id = GetLocationId(range.getBegin(), range.getEnd());
  AddTypeReferencesFromLocation(location_id, type);
}

}  // namespace indexer
}  // namespace oss_fuzz
