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
#include "absl/log/log.h"
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
#include "clang/Basic/OperatorKinds.h"
#include "clang/Basic/SourceLocation.h"
#include "clang/Basic/Specifiers.h"
#include "clang/Basic/TypeTraits.h"
#include "clang/Sema/Lookup.h"
#include "clang/Sema/Sema.h"
#include "llvm/ADT/APSInt.h"
#include "llvm/ADT/ArrayRef.h"
#include "llvm/ADT/MapVector.h"
#include "llvm/ADT/SmallPtrSet.h"
#include "llvm/ADT/SmallSet.h"
#include "llvm/ADT/SmallString.h"
#include "llvm/ADT/SmallVector.h"
#include "llvm/ADT/StringRef.h"
#include "llvm/Support/Casting.h"
#include "llvm/Support/raw_ostream.h"

namespace oss_fuzz {
namespace indexer {
namespace {

const clang::PrintingPolicy& GetPrintingPolicy() {
  static clang::PrintingPolicy static_policy = ([] {
    clang::PrintingPolicy policy({});
    policy.adjustForCPlusPlus();
    policy.SplitTemplateClosers = false;
    policy.SuppressTemplateArgsInCXXConstructors = true;
    return policy;
  })();
  return static_policy;
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
    const llvm::ArrayRef<clang::TemplateArgument> args,
    const clang::ASTContext& context) {
  // Without this, sugared types can lead to lookup misses.
  llvm::SmallVector<clang::TemplateArgument, 4> canonical_args;
  for (const clang::TemplateArgument& arg : args) {
    canonical_args.push_back(context.getCanonicalTemplateArgument(arg));
  }

  // XXX(kartynnik): `findSpecialization` is a non-`const` method because it can
  // lead to loading external specializations. Arguably this could have been
  // handled through `mutable` fields because logically this doesn't affect the
  // forthcoming behavior of the object.
  void* insert_pos = nullptr;
  return const_cast<clang::ClassTemplateDecl*>(class_template_decl)
      ->findSpecialization(canonical_args, insert_pos);
}

// Helper functions to find the closest explicit template specialization that
// matches the provided template arguments.
const clang::Decl* GetSpecializationDecl(
    const clang::ClassTemplateDecl* class_template_decl,
    const llvm::ArrayRef<clang::TemplateArgument> template_arguments,
    const clang::ASTContext& context) {
  class_template_decl = GetClassTemplateDefinition(class_template_decl);
  const clang::Decl* decl = class_template_decl;
  const auto* specialization_decl =
      FindSpecialization(class_template_decl, template_arguments, context);
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
    const clang::TemplateSpecializationType* type,
    const clang::ASTContext& context) {
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
                                   type->template_arguments(), context);
    } else if (llvm::isa<clang::TypeAliasTemplateDecl>(template_decl)) {
      return llvm::cast<clang::TypeAliasTemplateDecl>(template_decl)
          ->getTemplatedDecl();
    }
  }

  return decl;
}

const clang::Decl* GetSpecializationDecl(
    const clang::ClassTemplateSpecializationDecl* decl,
    const clang::ASTContext& context) {
  // If this is an explicit specialization, then there's no need to look for
  // the best matching specialization.
  if (decl->isExplicitSpecialization()) {
    return decl;
  }
  return GetSpecializationDecl(decl->getSpecializedTemplate(),
                               decl->getTemplateArgs().asArray(), context);
}

const clang::CXXRecordDecl* GetTemplatePrototypeRecordDecl(
    const clang::ClassTemplateSpecializationDecl* decl,
    const clang::ASTContext& context) {
  const clang::Decl* specialization_decl = GetSpecializationDecl(decl, context);
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

// `decl` is required to be a `clang::NamedDecl`.
// If it is inside a template instantiation, finds the context where it is
// instantiated from and finds the corresponding entity by name.
const clang::NamedDecl* GetTemplatePrototypeNamedDecl(
    const clang::Decl* decl, const clang::ASTContext& context) {
  const clang::NamedDecl* named_decl = llvm::dyn_cast<clang::NamedDecl>(decl);
  CHECK_NE(named_decl, nullptr);
  clang::DeclarationName field_name = named_decl->getDeclName();

  if (field_name.getAsString().empty()) {
    // E.g. for a `DecompositionDecl`.
    return nullptr;
  }
  const clang::DeclContext* template_context = nullptr;
  const clang::TemplateDecl* template_decl = nullptr;

  if (const auto* class_specialization_decl =
          llvm::dyn_cast<clang::ClassTemplateSpecializationDecl>(
              named_decl->getDeclContext())) {
    if (class_specialization_decl->isExplicitSpecialization()) {
      return nullptr;
    }
    if (const clang::CXXRecordDecl* template_definition =
            GetTemplatePrototypeRecordDecl(class_specialization_decl,
                                           context)) {
      template_context = template_definition;
      template_decl = template_definition->getDescribedClassTemplate();
    } else {
      return nullptr;
    }
  } else if (const auto* function_decl = llvm::dyn_cast<clang::FunctionDecl>(
                 named_decl->getDeclContext())) {
    if (const clang::FunctionDecl* instantiation_pattern =
            function_decl->getTemplateInstantiationPattern()) {
      template_context = instantiation_pattern;
      template_decl = instantiation_pattern->getDescribedFunctionTemplate();
    } else if (function_decl->getDescribedFunctionTemplate() &&
               function_decl->getDescribedFunctionTemplate()
                   ->getInstantiatedFromMemberTemplate()) {
      template_decl = function_decl->getDescribedFunctionTemplate()
                          ->getInstantiatedFromMemberTemplate();
      template_context = llvm::dyn_cast<clang::FunctionDecl>(
          template_decl->getTemplatedDecl());
    } else {
      return nullptr;
    }
  } else {
    return nullptr;
  }

  if (template_context) {
    // We are using `decls` instead of `fields` to also account for statics.
    for (const clang::Decl* inner_decl : template_context->decls()) {
      if (const auto* inner_named_decl =
              llvm::dyn_cast<clang::NamedDecl>(inner_decl)) {
        if (inner_named_decl->getDeclName() == field_name) {
          if (llvm::isa<clang::BindingDecl>(inner_named_decl)) {
            // TODO: Figure out if we can support these.
            return nullptr;
          }
          return inner_named_decl;
        }
      }
    }
  }

  if (template_decl) {
    // Look up template parameters as well.
    for (const clang::NamedDecl* template_parameter :
         *template_decl->getTemplateParameters()) {
      if (template_parameter->getDeclName() == field_name) {
        return template_parameter;
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

template <class TemplateArgumentType>
std::string FormatTemplateArguments(const clang::TemplateParameterList* params,
                                    llvm::ArrayRef<TemplateArgumentType> args) {
  llvm::SmallString<128> string;
  llvm::raw_svector_ostream stream(string);
  clang::printTemplateArgumentList(stream, args, GetPrintingPolicy(), params);
  return stream.str().str();
}

// Helper functions to generate the `<typename T, int S>` suffixes when handling
// templates.
std::string GetTemplateParameterSuffix(const clang::TemplateDecl* decl) {
  return FormatTemplateParameters(decl->getTemplateParameters());
}

std::string GetTemplateParameterSuffix(
    const clang::ClassTemplateSpecializationDecl* decl) {
  const clang::TemplateParameterList* params =
      decl->getSpecializedTemplate()->getTemplateParameters();
  if (const auto* partial_spec_decl =
          llvm::dyn_cast<clang::ClassTemplatePartialSpecializationDecl>(decl)) {
    if (const clang::ASTTemplateArgumentListInfo* args_as_written =
            partial_spec_decl->getTemplateArgsAsWritten()) {
      return FormatTemplateArguments(params, args_as_written->arguments());
    }
  }
  return FormatTemplateArguments(params, decl->getTemplateArgs().asArray());
}

std::string GetTemplateParameterSuffix(
    const clang::TemplateSpecializationType* type,
    const clang::ASTContext& context) {
  const auto* template_decl = type->getTemplateName().getAsTemplateDecl();
  if (llvm::isa<clang::ClassTemplateDecl>(template_decl)) {
    const auto* class_template_decl =
        llvm::cast<clang::ClassTemplateDecl>(template_decl);
    return GetTemplateParameterSuffix(FindSpecialization(
        class_template_decl, type->template_arguments(), context));
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

std::string GetTemplateParameterSuffix(
    const clang::VarTemplateSpecializationDecl* decl,
    const clang::ASTContext& context) {
  const clang::TemplateParameterList* params =
      decl->getSpecializedTemplate()->getTemplateParameters();
  if (const auto* partial_spec_decl =
          llvm::dyn_cast<clang::VarTemplatePartialSpecializationDecl>(decl)) {
    if (const clang::ASTTemplateArgumentListInfo* args_as_written =
            partial_spec_decl->getTemplateArgsAsWritten()) {
      return FormatTemplateArguments(params, args_as_written->arguments());
    }
  }
  return FormatTemplateArguments(params, decl->getTemplateArgs().asArray());
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

std::string GetNameSuffix(const clang::Decl* decl,
                          const clang::ASTContext& context) {
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
  } else if (llvm::isa<clang::VarDecl>(decl)) {
    const auto* var_decl = llvm::cast<clang::VarDecl>(decl);
    if (const auto* var_template_decl = var_decl->getDescribedVarTemplate()) {
      name_suffix = GetTemplateParameterSuffix(var_template_decl);
    } else if (const auto* var_template_specialization_decl =
                   llvm::dyn_cast<clang::VarTemplateSpecializationDecl>(decl)) {
      name_suffix =
          GetTemplateParameterSuffix(var_template_specialization_decl, context);
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

std::string GetNamePrefixForDeclContext(const clang::DeclContext* decl_context,
                                        const clang::ASTContext& ast_context,
                                        bool include_function_scope = true) {
  std::list<std::string> parts = {""};

  while (decl_context) {
    if (llvm::isa<clang::FunctionDecl>(decl_context)) {
      if (!include_function_scope) {
        // If we're not including function scopes, then we can stop when we
        // reach the first containing function.
        break;
      }

      const auto* parent_decl = llvm::cast<clang::Decl>(decl_context);
      parts.push_front(absl::StrCat(GetName(parent_decl),
                                    GetNameSuffix(parent_decl, ast_context)));
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
        parts.push_front(absl::StrCat(GetName(parent_decl),
                                      GetNameSuffix(parent_decl, ast_context)));
      }
    } else if (llvm::isa<clang::EnumDecl>(decl_context)) {
      const auto* enum_decl = llvm::cast<clang::EnumDecl>(decl_context);
      // The only time that an enum should appear in our name prefix is when it
      // is a c++11 scoped enum / enum class.
      if (enum_decl->isScoped() || enum_decl->isScopedUsingClassTag()) {
        const auto* parent_decl = llvm::cast<clang::Decl>(decl_context);
        parts.push_front(absl::StrCat(GetName(parent_decl),
                                      GetNameSuffix(parent_decl, ast_context)));
      }
    }
    decl_context = decl_context->getParent();
  }

  return absl::StrJoin(parts, "::");
}

std::string GetNamePrefix(const clang::Decl* decl,
                          const clang::ASTContext& ast_context) {
  if (llvm::isa<clang::ParmVarDecl>(decl)) {
    return {};
  }

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
  return GetNamePrefixForDeclContext(decl_context, ast_context,
                                     include_function_scope);
}

bool IsIgnoredImplicitDecl(const clang::Decl* decl) {
  // Don't index unreferenced implicit entities except implicit methods.
  // (We opt to declare all the implicit methods with a preference to report
  // e.g. an "implicitly defined" destructor over reporting it missing.)
  return decl->isImplicit() && !llvm::isa<clang::CXXMethodDecl>(decl);
}

bool IsNotInherited(const clang::Decl* decl) {
  if (decl->isImplicit() || llvm::isa<clang::CXXConstructorDecl>(decl) ||
      llvm::isa<clang::CXXDestructorDecl>(decl)) {
    return true;
  }
  // Assignment operators are not inherited.
  if (const auto* function_decl = llvm::dyn_cast<clang::FunctionDecl>(decl)) {
    if (function_decl->isOverloadedOperator() &&
        function_decl->getOverloadedOperator() == clang::OO_Equal) {
      return true;
    }
  }
  return false;
}

using SeenNames = llvm::SmallSet<clang::DeclarationName, 32>;

void CollectPotentialMemberNamesFromAncestors(
    const clang::CXXRecordDecl* class_decl, SeenNames& seen_names) {
  class_decl = class_decl->getDefinition();
  if (!class_decl) {
    return;
  }
  for (const auto& base_spec : class_decl->bases()) {
    if (const clang::CXXRecordDecl* base_decl =
            base_spec.getType()->getAsCXXRecordDecl();
        base_decl && (base_decl = base_decl->getDefinition())) {
      // We are using `decls` instead of `fields` to also account for statics.
      for (const auto* decl : base_decl->decls()) {
        if (const auto* named_decl = llvm::dyn_cast<clang::NamedDecl>(decl)) {
          const clang::DeclarationName& decl_name = named_decl->getDeclName();
          if (decl_name.getAsString().empty()) {
            continue;
          }
          if (!seen_names.contains(decl_name)) {
            // Process all the members with this name (e.g. method overloads).
            auto result = base_decl->lookup(named_decl->getDeclName());
            for (const auto* found_decl : result) {
              if (!IsNotInherited(found_decl)) {
                seen_names.insert(decl_name);
                break;
              }
            }
          }
        }
      }

      CollectPotentialMemberNamesFromAncestors(base_decl, seen_names);
    }
  }
}

bool IsCompleteClass(const clang::CXXRecordDecl* class_decl) {
  // According to `Sema::LookupQualifiedName` constraints for a `TagDecl`.
  return class_decl->isDependentContext() ||
         class_decl->isCompleteDefinition() || class_decl->isBeingDefined();
}

template <typename Action>
void ForAllInheritedMembers(clang::Sema& sema,
                            const clang::CXXRecordDecl* class_decl,
                            Action&& action) {
  CHECK_NE(class_decl, nullptr);
  if (!IsCompleteClass(class_decl)) {
    return;
  }

  SeenNames seen_names;
  CollectPotentialMemberNamesFromAncestors(class_decl, seen_names);

  for (const clang::DeclarationName& decl_name : seen_names) {
    clang::LookupResult lookup_result(
        sema, decl_name, {}, clang::Sema::LookupNameKind::LookupMemberName);
    lookup_result.suppressDiagnostics();
    // `LookupQualifiedName` requires a mutable context - in particular,
    // implicit methods can be lazily defined in the process.
    // However, the pattern of `const` usage there is awkward - at the time of
    // writing, `LookupDirect` takes it as a `const` pointer, then passed to
    // `DeclareImplicitMemberFunctionsWithName` which casts the `const` away...
    auto* mutable_class_decl = const_cast<clang::CXXRecordDecl*>(class_decl);
    sema.LookupQualifiedName(lookup_result, mutable_class_decl,
                             /*InUnqualifiedLookup=*/false);
    if (!lookup_result.isSingleResult() &&
        !lookup_result.isOverloadedResult()) {
      // Ambiguous lookups that require qualification are not instantiated.
      // However, qualified accesses (`A().B::x`) do count as references.
      continue;
    }
    for (const auto decl : lookup_result) {
      // Check that it is an inherited member and not one from the class itself.
      if (decl->getNonTransparentDeclContext()->getPrimaryContext() ==
          class_decl->getPrimaryContext()) {
        continue;
      }
      action(decl);
    }
  }
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

// The mapping from (not necessarily immediate) base classes defining a method
// to their definitions thereof.
using DefiningSuperBasesToMethods =
    llvm::SmallMapVector<const clang::CXXRecordDecl*,
                         const clang::CXXMethodDecl*, 16>;

template <typename EntityIdByDecl>
void AddVirtualMethodLinksImpl(
    const clang::CXXMethodDecl* prototype_method_decl,
    const clang::CXXRecordDecl* child_class_decl,
    const DefiningSuperBasesToMethods& defining_super_bases_to_methods,
    EntityId child_id, InMemoryIndex& index,
    EntityIdByDecl&& get_entity_id_for_decl, const clang::ASTContext& context) {
  llvm::SmallPtrSet<const clang::CXXRecordDecl*, 32> seen;
  llvm::SmallVector<const clang::CXXRecordDecl*, 32> to_visit;
  auto add_bases_to_visit = [&to_visit,
                             &seen](const clang::CXXRecordDecl* class_decl) {
    for (const auto& base : class_decl->bases()) {
      auto* base_cxx_record = base.getType()->getAsCXXRecordDecl();
      if (!base_cxx_record) {
        continue;
      }
      base_cxx_record = base_cxx_record->getDefinition();
      if (!base_cxx_record) {
        continue;
      }
      if (!seen.contains(base_cxx_record)) {
        to_visit.push_back(base_cxx_record);
        seen.insert(base_cxx_record);
      }
    }
  };
  add_bases_to_visit(child_class_decl);

  while (!to_visit.empty()) {
    const clang::CXXRecordDecl* base_cxx_record = to_visit.pop_back_val();

    const auto it = defining_super_bases_to_methods.find(base_cxx_record);
    if (it != defining_super_bases_to_methods.end()) {
      // There is a definition in `base_cxx_record` we can link to.
      const clang::CXXMethodDecl* overridden_method_decl = it->second;
      EntityId parent_id = get_entity_id_for_decl(overridden_method_decl);
      if (parent_id != kInvalidEntityId) {
        (void)index.GetVirtualMethodLinkId({parent_id, child_id});
      } else {
        LOG(DFATAL) << "Parent of virtual method "
                    << index.GetEntityById(child_id).full_name() << " in class "
                    << base_cxx_record->getQualifiedNameAsString()
                    << " is an invalid entity";
      }
      continue;
    }

    // `base_cxx_record` doesn't define this method directly.
    for (const auto [defining_super_base, overridden_method_decl] :
         defining_super_bases_to_methods) {
      if (!base_cxx_record->isDerivedFrom(defining_super_base)) {
        continue;
      }
      // Because it can be present in `base_cxx_record` only through inheritance
      // (see above), check if it was synthesized there from
      // `overridden_method_decl` in `defining_super_base`.
      const EntityId inherited_id =
          get_entity_id_for_decl(overridden_method_decl);
      if (inherited_id == kInvalidEntityId) {
        LOG(DFATAL) << "Parent of virtual method "
                    << index.GetEntityById(child_id).full_name() << " in class "
                    << defining_super_base->getQualifiedNameAsString()
                    << " is an invalid entity";
        continue;
      }
      const Entity& inherited_entity = index.GetEntityById(inherited_id);
      const std::string new_name_prefix =
          GetNamePrefixForDeclContext(base_cxx_record, context);
      // Re-synthesize it to get the ID of the synthetic entity.
      const EntityId parent_id = index.GetExistingEntityId(
          Entity(inherited_entity, /*new_name_prefix=*/new_name_prefix,
                 /*inherited_entity_id=*/inherited_id));
      if (parent_id == kInvalidEntityId) {
        // No such synthetic entity, likely due to name resolution ambiguity in
        // the base. Skip it and consider its immediate super-bases.
        add_bases_to_visit(base_cxx_record);
      } else {
        (void)index.GetVirtualMethodLinkId({parent_id, child_id});
      }
      // We can't break here - can have multiple bases with this virtual method.
    }
  }
}

const clang::CXXRecordDecl* GetRecordForType(const clang::QualType& type) {
  clang::QualType derived_type = type;
  if (const auto* pointer_type = type->getAs<clang::PointerType>()) {
    derived_type = pointer_type->getPointeeType();
  }
  if (derived_type->isDependentType()) {
    return nullptr;
  }
  const auto* record_type = derived_type->castAs<clang::RecordType>();
  CHECK(record_type);
  const clang::Decl* decl = record_type->getOriginalDecl();
  CHECK(decl);
  return llvm::cast<clang::CXXRecordDecl>(decl);
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
  if (auto* record_decl = llvm::dyn_cast<clang::CXXRecordDecl>(decl)) {
    if (record_decl->isInjectedClassName()) {
      // struct C {
      //   // C is implicitly declared here as a synonym for the class name.
      // };
      // C::C c; // same as "C c;"
      // Only index `C` in this case, and don't index `C::C`.
      return true;
    }

    if (IsADefinition(record_decl)) {
      SynthesizeInheritedMemberEntities(record_decl);
    }

    // We opt to declare all the implicit members with a preference to report
    // e.g. an "implicitly defined" destructor over reporting it missing.
    sema_.ForceDeclarationOfImplicitMembers(record_decl);
  }

  // As for FunctionDecl, we only need to add an entity for a RecordDecl if this
  // is the definition, or if there is no definition in this translation unit.
  if (IsADefinition(decl) || !decl->getDefinition()) {
    GetEntityIdForDecl(decl);
    AddReferencesForDecl(decl);
  }
  return true;
}

void AstVisitor::SynthesizeInheritedMemberEntities(
    const clang::CXXRecordDecl* class_decl) {
  CHECK(IsADefinition(class_decl));

  const std::string new_name_prefix = GetNamePrefixForDeclContext(
      /*decl_context=*/class_decl, /*ast_context=*/context_);
  ForAllInheritedMembers(sema_, class_decl, [&](const clang::Decl* decl) {
    const EntityId inherited_id = GetEntityIdForDecl(decl);
    if (inherited_id == kInvalidEntityId) {
      return;
    }
    const Entity& inherited_entity = index_.GetEntityById(inherited_id);
    const Entity synth_entity(inherited_entity,
                              /*new_name_prefix=*/new_name_prefix,
                              /*inherited_entity_id=*/inherited_id);
    const EntityId synth_id = index_.GetEntityId(synth_entity);

    if (inherited_entity.is_virtual_method()) {
      AddSynthesizedVirtualMethodLinks(llvm::cast<clang::CXXMethodDecl>(decl),
                                       class_decl, synth_id);
    }
  });
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
    decl = GetSpecializationDecl(specialization_decl, context_);
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
    const auto* function_decl = llvm::cast<clang::FunctionDecl>(decl);
    if (function_decl->isTemplateInstantiation()) {
      function_decl = function_decl->getTemplateInstantiationPattern();
    } else if (function_decl->getTemplateSpecializationInfo()) {
      const auto* tmp_info = function_decl->getTemplateSpecializationInfo();
      function_decl = tmp_info->getFunction();
    }

    decl = function_decl;
    const auto* func_template = function_decl->getDescribedFunctionTemplate();
    if (func_template) {
      decl = func_template;
    }
  }

  // Same for variable template declarations.
  if (llvm::isa<clang::VarDecl>(decl)) {
    const auto* var_decl = llvm::cast<clang::VarDecl>(decl);
    const auto* var_template_decl = var_decl->getDescribedVarTemplate();
    if (var_template_decl) {
      decl = var_template_decl;
    }
  }

  // Same for type alias template declarations.
  if (llvm::isa<clang::TypeAliasDecl>(decl)) {
    const auto* type_alias_decl = llvm::cast<clang::TypeAliasDecl>(decl);
    const auto* type_alias_template_decl =
        type_alias_decl->getDescribedTemplate();
    if (type_alias_template_decl) {
      decl = type_alias_template_decl;
    }
  }

  // b/438675191: Workaround for a `libclang` bug (incorrect start location of
  // abbreviated function templates stemming from a missing `template` keyword).
  if (const auto* function_template_decl =
          llvm::dyn_cast<clang::FunctionTemplateDecl>(decl);
      function_template_decl &&
      function_template_decl->getBeginLoc().isInvalid()) {
    return GetLocationId(
        function_template_decl->getTemplatedDecl()->getBeginLoc(),
        function_template_decl->getEndLoc());
  }

  // If we reach here then we have updated decl to point to the correct location
  // already.
  return GetLocationId(decl->getBeginLoc(), decl->getEndLoc());
}

std::optional<SubstituteRelationship>
AstVisitor::GetTemplateSubstituteRelationship(
    const clang::Decl* template_decl, const clang::Decl* original_decl) {
  if (template_decl == nullptr) {
    return std::nullopt;
  }

  EntityId template_entity_id = GetEntityIdForDecl(template_decl);
  if (template_entity_id == kInvalidEntityId) {
    // `original_decl` might have been materialized with `for_reference`.
    if (!IsIgnoredImplicitDecl(original_decl)) {
      std::string str;
      llvm::raw_string_ostream stream(str);
      stream << "Please report an indexer issue marked 'TEMPLATE':\n";
      ReportTranslationUnit(stream, context_);
      stream << "Original Decl:\n";
      original_decl->dump(stream);
      stream << "Template prototype Decl:\n";
      template_decl->dump(stream);
      llvm::errs() << str;
    }
    return std::nullopt;
  }

  const Entity& template_entity = index_.GetEntityById(template_entity_id);
  const auto relationship_kind =
      SubstituteRelationship::Kind::kIsTemplateInstantiationOf;
  if (const auto& next_relationship = template_entity.substitute_relationship();
      next_relationship && next_relationship->kind() == relationship_kind) {
    // Contract consecutive references to point to the ultimate prototype.
    template_entity_id = next_relationship->substitute_entity_id();
  }
  return SubstituteRelationship(relationship_kind, template_entity_id);
}

// See the description of the `VirtualMethodLink` type for a discussion.
void AstVisitor::AddVirtualMethodLinks(const clang::CXXMethodDecl* method_decl,
                                       EntityId child_id) {
  // For an actual virtual method, trace the chains to its prototypes, if any.
  if (method_decl->overridden_methods().empty()) {
    return;
  }
  DefiningSuperBasesToMethods defining_super_bases_to_methods;
  for (const clang::CXXMethodDecl* overridden_method_decl :
       method_decl->overridden_methods()) {
    const clang::CXXRecordDecl* overridden_method_record =
        overridden_method_decl->getParent();
    defining_super_bases_to_methods.insert(
        {overridden_method_record, overridden_method_decl});
  }
  AddVirtualMethodLinksImpl(
      method_decl, method_decl->getParent(), defining_super_bases_to_methods,
      child_id, index_,
      [&](const clang::Decl* decl) -> EntityId {
        return GetEntityIdForDecl(decl);
      },
      context_);
}

void AstVisitor::AddSynthesizedVirtualMethodLinks(
    const clang::CXXMethodDecl* prototype_method_decl,
    const clang::CXXRecordDecl* child_class_decl, EntityId child_id) {
  DefiningSuperBasesToMethods defining_super_bases_to_methods;
  // For a synthesized entity, trace the chain(s) back to the origin class.
  defining_super_bases_to_methods.insert(
      {prototype_method_decl->getParent(), prototype_method_decl});
  AddVirtualMethodLinksImpl(
      prototype_method_decl, child_class_decl, defining_super_bases_to_methods,
      child_id, index_,
      [&](const clang::Decl* decl) -> EntityId {
        return GetEntityIdForDecl(decl);
      },
      context_);
}

EntityId AstVisitor::GetEntityIdForDecl(const clang::Decl* decl,
                                        bool for_reference) {
  auto it = decl_to_entity_id_.find(decl);
  if (it != decl_to_entity_id_.end()) {
    const CachedEntityId& cached = it->second;
    if (for_reference || !cached.for_reference_only) {
      return cached.entity_id;
    }
  }
  std::optional<Entity> entity = GetEntityForDecl(decl, for_reference);
  if (entity) {
    const EntityId id = index_.GetEntityId(*entity);
    decl_to_entity_id_.insert_or_assign(it, decl, {id, for_reference});
    if (entity->is_virtual_method()) {
      const auto method_decl = llvm::cast<clang::CXXMethodDecl>(decl);
      AddVirtualMethodLinks(method_decl, id);
    }
    return id;
  }
  if (for_reference) {
    // If even `for_reference` yields an invalid entity, we can cache that.
    decl_to_entity_id_.insert(
        it, {decl, {kInvalidEntityId, /*for_reference_only=*/false}});
  }
  return kInvalidEntityId;
}

std::optional<Entity> AstVisitor::GetEntityForDecl(const clang::Decl* decl,
                                                   bool for_reference,
                                                   LocationId location_id) {
  CHECK_NE(decl, nullptr);
  // Unless they are referenced, do not index `IsIgnoredImplicitDecl` subjects.
  if (!for_reference && IsIgnoredImplicitDecl(decl)) {
    return std::nullopt;
  }

  // Handle assignments of lambda types, as we need to get the entity for the
  // lambda::operator() rather than the implicit invisible lambda class.
  if (llvm::isa<clang::CXXRecordDecl>(decl)) {
    auto* function_decl = llvm::cast<clang::CXXRecordDecl>(decl);
    if (function_decl->isLambda()) {
      return GetEntityForDecl(function_decl->getLambdaCallOperator(),
                              location_id);
    }
  }

  // Similarly, for ClassTemplateDecl we want the underlying CXXRecordDecl and
  // not the template wrapper decl.
  if (llvm::isa<clang::ClassTemplateDecl>(decl)) {
    const auto* class_template_decl =
        llvm::cast<clang::ClassTemplateDecl>(decl);
    decl = class_template_decl->getTemplatedDecl();
  }

  // Resolve FunctionTemplateDecl to the underlying FunctionDecl.
  if (llvm::isa<clang::FunctionTemplateDecl>(decl)) {
    const auto* function_template_decl =
        llvm::cast<clang::FunctionTemplateDecl>(decl);
    decl = function_template_decl->getTemplatedDecl();
  }

  // Resolve VarTemplateDecl to the underlying VarDecl.
  if (llvm::isa<clang::VarTemplateDecl>(decl)) {
    const auto* var_template_decl = llvm::cast<clang::VarTemplateDecl>(decl);
    decl = var_template_decl->getTemplatedDecl();
  }

  // Resolve TypeAliasTemplateDecl to the underlying TypeAliasDecl.
  if (llvm::isa<clang::TypeAliasTemplateDecl>(decl)) {
    const auto* type_template_decl =
        llvm::cast<clang::TypeAliasTemplateDecl>(decl);
    decl = type_template_decl->getTemplatedDecl();
  }

  // Then handle structured binding.
  if (llvm::isa<clang::BindingDecl>(decl)) {
    auto* binding_decl = llvm::cast<clang::BindingDecl>(decl);
    decl = binding_decl->getHoldingVar();
    // It's possible that we don't have a holding var here.
    if (!decl) {
      return std::nullopt;
    }
  }

  // Then resolve from the declaration to the definition of the entity.
  if (llvm::isa<clang::VarDecl>(decl)) {
    auto* var_decl = llvm::cast<clang::VarDecl>(decl);
    if (!var_decl->isThisDeclarationADefinition() &&
        var_decl->getDefinition()) {
      decl = var_decl->getDefinition();
    }
  } else if (llvm::isa<clang::TagDecl>(decl)) {
    auto* tag_decl = llvm::cast<clang::TagDecl>(decl);
    if (!tag_decl->isThisDeclarationADefinition() &&
        tag_decl->getDefinition()) {
      decl = tag_decl->getDefinition();
    }
  } else if (llvm::isa<clang::FunctionDecl>(decl)) {
    auto* function_decl = llvm::cast<clang::FunctionDecl>(decl);
    if (!function_decl->isThisDeclarationADefinition() &&
        function_decl->getDefinition()) {
      decl = function_decl->getDefinition();
    }
  }
  // Defer getting the location in case the entity is invalid.
  auto get_location_id = [&]() {
    return location_id == kInvalidLocationId ? GetLocationId(decl)
                                             : location_id;
  };

  const std::string name = GetName(decl);
  if (name.empty()) {
    return std::nullopt;
  }
  const std::string name_prefix = GetNamePrefix(decl, context_);
  const std::string name_suffix = GetNameSuffix(decl, context_);

  std::optional<SubstituteRelationship> substitute_relationship;
  if (llvm::isa<clang::VarDecl>(decl) || llvm::isa<clang::FieldDecl>(decl) ||
      llvm::isa<clang::NonTypeTemplateParmDecl>(decl)) {
    if (decl->isImplicit() || llvm::isa<clang::DecompositionDecl>(decl)) {
      // Implicit `VarDecl`s encountered were range `for` loop variables;
      // implicit `FieldDecl`s were unnamed anonymous struct/union fields
      // (see `FieldDecl::isAnonymousStructOrUnion`).
      // `DecompositionDecl` is unnamed but inherits from `VarDecl`.
      return std::nullopt;
    }

    if (llvm::isa<clang::FieldDecl>(decl) || llvm::isa<clang::VarDecl>(decl)) {
      // Check for template instantiation.
      substitute_relationship = GetTemplateSubstituteRelationship(
          GetTemplatePrototypeNamedDecl(decl, context_), decl);
    }
    return Entity(Entity::Kind::kVariable, name_prefix, name, name_suffix,
                  get_location_id(), /*is_incomplete=*/false,
                  /*is_weak=*/false, substitute_relationship);
  } else if (llvm::isa<clang::RecordDecl>(decl)) {
    const auto* record_decl = llvm::cast<clang::RecordDecl>(decl);
    bool is_incomplete = !record_decl->getDefinition();
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

        substitute_relationship = GetTemplateSubstituteRelationship(
            GetTemplatePrototypeRecordDecl(class_template_specialization_decl,
                                           context_),
            class_template_specialization_decl);
      }
    }
    return Entity(Entity::Kind::kClass, name_prefix, name, name_suffix,
                  get_location_id(), is_incomplete, /*is_weak=*/false,
                  substitute_relationship);
  } else if (llvm::isa<clang::EnumDecl>(decl)) {
    substitute_relationship = GetTemplateSubstituteRelationship(
        GetTemplatePrototypeNamedDecl(decl, context_), decl);
    return Entity(Entity::Kind::kEnum, name_prefix, name, name_suffix,
                  get_location_id(), /*is_incomplete=*/false,
                  /*is_weak=*/false, substitute_relationship);
  } else if (llvm::isa<clang::EnumConstantDecl>(decl)) {
    const auto* enum_constant_decl = llvm::cast<clang::EnumConstantDecl>(decl);
    substitute_relationship = GetTemplateSubstituteRelationship(
        GetTemplatePrototypeNamedDecl(decl, context_), decl);
    return Entity(Entity::Kind::kEnumConstant, name_prefix, name, name_suffix,
                  get_location_id(), /*is_incomplete=*/false, /*is_weak=*/false,
                  substitute_relationship,
                  /*enum_value=*/GetEnumValue(enum_constant_decl));
  } else if (llvm::isa<clang::TemplateTypeParmDecl>(decl) ||
             llvm::isa<clang::TypedefNameDecl>(decl)) {
    substitute_relationship = GetTemplateSubstituteRelationship(
        GetTemplatePrototypeNamedDecl(decl, context_), decl);
    return Entity(Entity::Kind::kType, name_prefix, name, name_suffix,
                  get_location_id(), /*is_incomplete=*/false, /*is_weak=*/false,
                  substitute_relationship);
  } else if (llvm::isa<clang::FunctionDecl>(decl)) {
    const auto* function_decl = llvm::cast<clang::FunctionDecl>(decl);
    bool is_incomplete = IsIncompleteFunction(function_decl);
    bool is_weak = !is_incomplete && function_decl->hasAttr<clang::WeakAttr>();
    Entity::VirtualMethodKind virtual_method_kind =
        Entity::VirtualMethodKind::kNotAVirtualMethod;
    if (const auto* method_decl =
            llvm::dyn_cast<clang::CXXMethodDecl>(function_decl)) {
      if (method_decl->isVirtual()) {
        virtual_method_kind = method_decl->isPureVirtual()
                                  ? Entity::VirtualMethodKind::kPureVirtual
                                  : Entity::VirtualMethodKind::kNonPureVirtual;
      }
    }

    // Note: Implicit methods are generally defined after template
    // instantiation, but an implicit comparison operator coming from (C++20)
    //   constexpr operator<=>(const TemplatedClass<T>& other);
    // can be instantiated by class template instantiations.
    // In this case we report the instantiation via `kIsTemplateInstantiationOf`
    // which refers to an implicit method in the template
    // (`kIsImplicitlyDefinedFor`).
    //
    // In contrast, an implicit destructor of an (implicit) template
    // instantiation will have `kIsImplicitlyDefinedFor` which in turn
    // has a 'kIsTemplateInstantiationOf`.

    // Check for template instantiation.
    const clang::Decl* function_template = nullptr;
    if (function_decl->getTemplateInstantiationPattern()) {
      function_template = function_decl->getTemplateInstantiationPattern();
    } else if (function_decl->getDescribedFunctionTemplate() &&
               function_decl->getDescribedFunctionTemplate()
                   ->getInstantiatedFromMemberTemplate()) {
      function_template = function_decl->getDescribedFunctionTemplate()
                              ->getInstantiatedFromMemberTemplate();
    }
    if (function_template) {
      substitute_relationship =
          GetTemplateSubstituteRelationship(function_template, decl);
    }

    if (!substitute_relationship) {
      if (const auto method_decl =
              llvm::dyn_cast<clang::CXXMethodDecl>(function_decl)) {
        // Check for an implicitly defined method.
        if (!substitute_relationship && method_decl->isImplicit()) {
          auto parent_class = method_decl->getParent();
          if (parent_class->getName().empty()) {
            // An anonymous struct's/union's implicit method; ignore.
            return std::nullopt;
          }
          auto implicitly_defined_for_entity_id =
              GetEntityIdForDecl(parent_class);
          if (implicitly_defined_for_entity_id == kInvalidEntityId) {
            // Case in point: Implicitly defined `struct __va_list_tag`.
            return std::nullopt;
          } else {
            substitute_relationship = {
                SubstituteRelationship::Kind::kIsImplicitlyDefinedFor,
                implicitly_defined_for_entity_id};
          }
        }
      }
    }
    return Entity(Entity::Kind::kFunction, name_prefix, name, name_suffix,
                  get_location_id(), is_incomplete, is_weak,
                  substitute_relationship, /*enum_value=*/std::nullopt,
                  /*virtual_method_kind=*/virtual_method_kind);
  }

  return std::nullopt;
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
        GetSpecializationDecl(specialization_type, context_);
    if (specialization_decl) {
      auto entity_id = GetEntityIdForDecl(specialization_decl,
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
    // template ClassTemplateDecl, and for partial specializations we also
    // need to override the name_suffix generation with information that is only
    // stored in the TemplateSpecializationType.
    if (decl_location_id != kInvalidLocationId) {
      if (template_decl &&
          llvm::isa<clang::TypeAliasTemplateDecl>(template_decl)) {
        std::string name_prefix = GetNamePrefix(template_decl, context_);
        std::string name = GetName(template_decl);
        std::string name_suffix =
            GetTemplateParameterSuffix(specialization_type, context_);

        auto* alias_template_decl =
            llvm::cast<clang::TypeAliasTemplateDecl>(template_decl);
        auto entity_id = index_.GetEntityId(
            {Entity::Kind::kType, name_prefix, name, name_suffix,
             decl_location_id,
             /*is_incomplete=*/false, /*is_weak=*/false,
             SubstituteRelationship(
                 SubstituteRelationship::Kind::kIsTemplateInstantiationOf,
                 GetEntityIdForDecl(alias_template_decl->getTemplatedDecl(),
                                    /*for_reference=*/true))});
        if (entity_id != kInvalidEntityId) {
          (void)index_.GetReferenceId({entity_id, location_id});
        }
      }
    }

    // Type declaration becomes the instantiation of the underlying template.
    type_decl = type->getAsTagDecl();
    if (type_decl) {
      auto entity_id = GetEntityIdForDecl(type_decl, /*for_reference=*/true);
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
      auto entity_id = GetEntityIdForDecl(type_decl, /*for_reference=*/true);

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
    if (const auto* method_decl = llvm::dyn_cast<clang::CXXMethodDecl>(decl)) {
      for (const clang::CXXMethodDecl* overridden_method :
           method_decl->overridden_methods()) {
        AddDeclReferenceForSourceRange(range, overridden_method);
      }
    }
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
        const auto* type = method_decl->getParent()
                               ->getASTContext()
                               .getCanonicalTagType(method_decl->getParent())
                               .getTypePtr();
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
        const auto* type =
            constructor_decl->getParent()
                ->getASTContext()
                .getCanonicalTagType(constructor_decl->getParent())
                .getTypePtr();
        if (type) {
          AddTypeReferencesForSourceRange(expr->getSourceRange(), type);
        }
      }
    }
  } else if (llvm::isa<clang::DeclRefExpr>(expr)) {
    decl = llvm::cast<clang::DeclRefExpr>(expr)->getDecl();
  } else if (llvm::isa<clang::MemberExpr>(expr)) {
    const auto* member_expr = llvm::cast<clang::MemberExpr>(expr);
    const clang::ValueDecl* value_decl = member_expr->getMemberDecl();
    decl = value_decl;
    if (clang::Expr* base = member_expr->getBase()) {
      AddReferencesForExpr(base);

      // Check if the call can be devirtualized (the type is known precisely,
      // or either the member function or its defining class are marked `final`
      // etc.) Add a reference to the devirtualized method as well in that case.
      if (const auto* method_decl =
              llvm::dyn_cast<clang::CXXMethodDecl>(value_decl);
          method_decl && method_decl->isVirtual()) {
        if (const clang::CXXMethodDecl* devirtualized_method_decl =
                method_decl->getDevirtualizedMethod(base,
                                                    /*IsAppleKext=*/false);
            devirtualized_method_decl &&
            devirtualized_method_decl != method_decl) {
          AddDeclReferenceForSourceRange(expr->getSourceRange(),
                                         devirtualized_method_decl);
        }
      }

      // Check if the access is through an inheriting descendant, in which case
      // we add a cross-reference to the corresponding synthetic entity.
      //
      // Skip the case of an explicit qualification (`instance.Base::method`)
      // because it is commonly used for members not accessible through the
      // instance directly (for disambiguation).
      if (!member_expr->getQualifierLoc()) {
        if (const auto* expr_record_decl =
                GetRecordForType(base->IgnoreParenBaseCasts()->getType())) {
          const clang::DeclContext* decl_context =
              value_decl->getNonTransparentDeclContext();
          // If the base expression is not of the same record type as the parent
          // of the retrieved member...
          if (const auto* record_decl =
                  llvm::dyn_cast<clang::CXXRecordDecl>(decl_context);
              record_decl && record_decl->getCanonicalDecl() !=
                                 expr_record_decl->getCanonicalDecl()) {
            // ...add synthetic entity cross-references.
            AddSyntheticMemberReference(expr_record_decl, value_decl,
                                        expr->getSourceRange());
          }
        }
      }
    }
  } else if (llvm::isa<clang::LambdaExpr>(expr)) {
    decl = llvm::cast<clang::LambdaExpr>(expr)
               ->getLambdaClass()
               ->getLambdaCallOperator();
  }

  if (decl) {
    AddDeclReferenceForSourceRange(expr->getSourceRange(), decl);
  }
}

void AstVisitor::AddSyntheticMemberReference(
    const clang::CXXRecordDecl* child_class,
    const clang::ValueDecl* inherited_member, const clang::SourceRange& range) {
  const EntityId base_member_entity_id = GetEntityIdForDecl(inherited_member);
  if (base_member_entity_id == kInvalidEntityId) {
    return;
  }
  const Entity& base_member_entity =
      index_.GetEntityById(base_member_entity_id);
  const Entity synthetic_inherited_member = Entity(
      base_member_entity, GetNamePrefixForDeclContext(child_class, context_),
      /*inherited_entity_id=*/base_member_entity_id);
  const EntityId synthetic_inherited_member_id =
      index_.GetEntityId(synthetic_inherited_member);
  auto location_id = GetLocationId(range.getBegin(), range.getEnd());
  (void)index_.GetReferenceId({synthetic_inherited_member_id, location_id});
}

void AstVisitor::AddDeclReferenceForSourceRange(const clang::SourceRange& range,
                                                const clang::Decl* decl) {
  auto entity_id = GetEntityIdForDecl(decl, /*for_reference=*/true);
  auto location_id = GetLocationId(range.getBegin(), range.getEnd());

  if (entity_id != kInvalidEntityId && location_id != kInvalidLocationId) {
    (void)index_.GetReferenceId({entity_id, location_id});
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
