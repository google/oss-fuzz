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

// Defines the main types used for indexing, at the lowest level. These types
// explicitly don't use pointers to express relationships to allow simple
// serialization.

#ifndef OSS_FUZZ_INFRA_INDEXER_INDEX_TYPES_H_
#define OSS_FUZZ_INFRA_INDEXER_INDEX_TYPES_H_

#include <compare>
#include <cstdint>
#include <optional>
#include <string>
#include <utility>
#include <vector>

#include "absl/log/check.h"
#include "absl/strings/string_view.h"

namespace oss_fuzz {
namespace indexer {
namespace testing_internal {
class TestPeer;
}  // namespace testing_internal
class InMemoryIndex;

using LocationId = uint64_t;
using EntityId = uint64_t;
using ReferenceId = uint64_t;
using VirtualMethodLinkId = uint64_t;
constexpr LocationId kInvalidLocationId = 0xffffffffffffffffull;
constexpr EntityId kInvalidEntityId = 0xffffffffffffffffull;

inline bool IsRealPath(absl::string_view path) {
  // Examples of built-in paths: `<built-in>` and `<command-line>`.
  return !path.empty() && !path.starts_with('<');
}

// Represents a source-file location.
class Location {
 public:
  Location(absl::string_view path, uint32_t start_line, uint32_t end_line);

  static Location WholeFile(absl::string_view path) {
    return Location(path, /*start_line=*/0, /*end_line=*/0);
  }

  inline const std::string& path() const { return path_; }
  inline uint32_t start_line() const { return start_line_; }
  inline uint32_t end_line() const { return end_line_; }

  inline bool is_real() const { return IsRealPath(path()); }
  inline bool is_whole_file() const {
    return start_line_ == 0 && end_line_ == 0;
  }

 private:
  friend class InMemoryIndex;

  std::string path_;
  uint32_t start_line_;
  uint32_t end_line_;
};

bool operator==(const Location& lhs, const Location& rhs);
std::strong_ordering operator<=>(const Location& lhs, const Location& rhs);

template <typename H>
H AbslHashValue(H h, const Location& location) {
  return H::combine(std::move(h), location.path(), location.start_line(),
                    location.end_line());
}

// Represents a relationship whereby an entity's source code is shown in lieu of
// that of another entity, typically because the latter is not explicitly
// defined in code.
class SubstituteRelationship {
 public:
  enum class Kind : uint8_t {
    // This entity is instantiated from the substitute entity (a template).
    // Example: Looking up Foo<int> when only Foo<T> implementation is provided.
    kIsTemplateInstantiationOf = 1,

    // This entity is implicitly defined for the substitute entity (but not in
    // the sense of being instantiated from a template or inherited).
    //
    // Example: An implicit constructor / destructor is defined for a class.
    //   Even if the class is a template instantiation, these implicit methods
    //   are defined post-instantiation (as in `FrontendTest.TemplateMemberFn`).
    //
    // Non-example: Implicit `operator==` instantiation from its counterpart
    //   `operator==` implicitly defined in a class template by
    //     const auto operator<=>(...) const = default;
    //   In this case that template `operator==` will be a
    //   `kIsTemplateInstantiationOf` substitute which, in turn, will have a
    //   `kIsImplicitlyDefinedFor` one, specifically the class template.
    //   (See `FrontendTest.ImplicitComparisonInstantiation` for this
    //   situation.)
    kIsImplicitlyDefinedFor = 2,

    // This entity's implementation is inherited from the base class and not
    // overridden.
    // (We report it as "this implementation is inherited from another" with a
    // slight abuse of wording.)
    kIsInheritedFrom = 3,
  };

  SubstituteRelationship(Kind kind, EntityId entity_id)
      : kind_(kind), entity_id_(entity_id) {
    CHECK_NE(entity_id, kInvalidEntityId);
  }

  Kind kind() const { return kind_; }
  EntityId substitute_entity_id() const { return entity_id_; }

  bool operator==(const SubstituteRelationship&) const = default;
  std::strong_ordering operator<=>(const SubstituteRelationship&) const =
      default;

 private:
  friend class Entity;
  friend class InMemoryIndex;

  Kind kind_;
  EntityId entity_id_;
};

template <typename H>
H AbslHashValue(H h, const SubstituteRelationship& relationship) {
  return H::combine(std::move(h), relationship.kind(),
                    relationship.substitute_entity_id());
}

// Represents a source-level entity definition.
class Entity {
 public:
  enum class Kind : uint8_t {
    // #define Macro ...
    kMacro = 1,
    // enum Enum { ... }
    kEnum = 2,
    // enum ... { EnumConstant = ... }
    kEnumConstant = 3,
    // int Variable = ...
    kVariable = 4,
    // int Function() { ... }
    kFunction = 5,
    // class Class { ... }; struct Class { ... };
    kClass = 6,
    // typedef Type int; using Type = int; union Type { ... };
    kType = 7,
  };

  enum class VirtualMethodKind : uint8_t {
    kNotAVirtualMethod = 0,
    kPureVirtual = 1,
    kNonPureVirtual = 2,
  };

  Entity(Kind kind, absl::string_view name_prefix, absl::string_view name,
         absl::string_view name_suffix, LocationId location_id,
         bool is_incomplete = false, bool is_weak = false,
         std::optional<SubstituteRelationship> substitute_relationship =
             std::nullopt,
         std::optional<std::string> enum_value = std::nullopt,
         VirtualMethodKind virtual_method_kind =
             VirtualMethodKind::kNotAVirtualMethod);

  // Allows to create a copy of `entity` with the ID field values replaced.
  template <class TEntity>
  Entity(TEntity&& entity, LocationId new_location_id,
         std::optional<EntityId> new_substitute_entity_id)
      : Entity(std::forward<TEntity>(entity)) {
    location_id_ = new_location_id;
    CHECK_EQ(substitute_relationship_.has_value(),
             new_substitute_entity_id.has_value());
    if (substitute_relationship_.has_value()) {
      substitute_relationship_->entity_id_ = *new_substitute_entity_id;
    }
  }

  // Allows to create a copy of `entity` inheriting its implementation.
  template <class TEntity>
  Entity(TEntity&& entity, absl::string_view new_name_prefix,
         EntityId inherited_entity_id)
      : Entity(std::forward<TEntity>(entity)) {
    name_prefix_ = new_name_prefix;
    substitute_relationship_ = SubstituteRelationship(
        SubstituteRelationship::Kind::kIsInheritedFrom, inherited_entity_id);
  }

  inline Kind kind() const { return kind_; }
  inline bool is_incomplete() const { return is_incomplete_; }
  inline bool is_weak() const { return is_weak_; }
  inline const std::string& name_prefix() const { return name_prefix_; }
  inline const std::string& name() const { return name_; }
  inline const std::string& name_suffix() const { return name_suffix_; }
  inline std::string full_name() const {
    return name_prefix() + name() + name_suffix();
  }
  inline LocationId location_id() const { return location_id_; }
  inline const std::optional<SubstituteRelationship>& substitute_relationship()
      const {
    return substitute_relationship_;
  }
  inline const std::optional<std::string>& enum_value() const {
    return enum_value_;
  }
  inline bool is_virtual_method() const {
    return virtual_method_kind_ != VirtualMethodKind::kNotAVirtualMethod;
  }
  inline VirtualMethodKind virtual_method_kind() const {
    return virtual_method_kind_;
  }

 private:
  friend class InMemoryIndex;
  friend class testing_internal::TestPeer;

  Kind kind_;

  // If an Entity is not complete, then it is a forward declaration. Incomplete
  // entries could be removed/merged with the corresponding complete Entities
  // during merge.
  bool is_incomplete_;

  // If the entity is weak, it should be overridden by strong entities at link
  // time.
  // Always false for incomplete entities.
  bool is_weak_;

  // Name is split into three components for storage and lookup.
  // "foo::bar::Baz(int qux)"
  //   name_prefix = "foo::bar::"
  //   name        = "Baz"
  //   name_suffix = "(int qux)"
  //
  // The only mandatory component is `name`, the other two are optional and may
  // not be present depending on the entity kind.
  std::string name_prefix_;
  std::string name_;
  std::string name_suffix_;

  LocationId location_id_;

  std::optional<SubstituteRelationship> substitute_relationship_;

  // Tracks the decimal value of an enum constant (only for `kEnumConstant`).
  // (A string to support both signed and unsigned 64-bit values - and beyond,
  // like the `__int128` extension.)
  std::optional<std::string> enum_value_;

  VirtualMethodKind virtual_method_kind_;
};

bool operator==(const Entity& lhs, const Entity& rhs);
std::strong_ordering operator<=>(const Entity& lhs, const Entity& rhs);

template <typename H>
H AbslHashValue(H h, const Entity& entity) {
  return H::combine(std::move(h), entity.kind(), entity.is_incomplete(),
                    entity.is_weak(), entity.name(), entity.name_prefix(),
                    entity.name_suffix(), entity.location_id(),
                    entity.substitute_relationship(), entity.enum_value(),
                    entity.virtual_method_kind());
}

// Represents a source-level reference to an entity. This may be an implicit or
// "hidden" reference that doesn't involve explicitly mentioning the entity by
// name.
class Reference {
 public:
  Reference(EntityId entity_id, LocationId location_id);

  EntityId entity_id() const { return entity_id_; }
  LocationId location_id() const { return location_id_; }

 private:
  friend class InMemoryIndex;

  EntityId entity_id_;
  LocationId location_id_;
};

bool operator==(const Reference& lhs, const Reference& rhs);
std::strong_ordering operator<=>(const Reference& lhs, const Reference& rhs);

template <typename H>
H AbslHashValue(H h, const Reference& reference) {
  return H::combine(std::move(h), reference.entity_id(),
                    reference.location_id());
}

// Represents a link between two virtual member functions.
// (Note that the C++ standard doesn't use the term "method" but we follow
// Clang's liberal approach of `CXXMethodDecl` for brevity.)
//
// We mostly track immediate parent-child relationships to be able to
// answer the question "What virtual method implementations can be invoked as
// `ptr->method()`?" even for `*ptr` being of a class that doesn't override, but
// only inherits a virtual method `child`.
// The only exception to this is when the immediate parent doesn't have the
// method due to name resolution ambiguity / an own set of overloads for this
// method hiding the overload in question, in which case we skip to the lowest
// ancestor(s) that do(es) have it:
//   struct A { virtual void X() {} };
//   struct B { virtual int X(int) { return 0; } };
//   // Has no `X(int)` due to its own overload set for X.
//   struct C: A, B { void X() override {} };
//   // `X(int)` can still be overridden through it though!
//   // We link `D::X(int)` directly to `B::X(int)`, bypassing `C`.
//   struct D: C { int X(int) override { return 13; } };
// The same behavior is observed when we remove the `X()` override from `C`
// since `C::X()` is an ambiguity.
class VirtualMethodLink {
 public:
  // `parent` and `child` should point to `Entity::Kind::kFunction` entities
  // with `is_virtual_method() == true`.
  VirtualMethodLink(EntityId parent, EntityId child)
      : parent_(parent), child_(child) {
    CHECK_NE(parent, kInvalidEntityId);
    CHECK_NE(child, kInvalidEntityId);
  }

  EntityId parent() const { return parent_; }
  EntityId child() const { return child_; }

  bool operator==(const VirtualMethodLink&) const = default;
  std::strong_ordering operator<=>(const VirtualMethodLink&) const = default;

 private:
  EntityId parent_;
  EntityId child_;
};

template <typename H>
H AbslHashValue(H h, const VirtualMethodLink& link) {
  return H::combine(std::move(h), link.parent(), link.child());
}

// A simple holder for a sorted index, used as an interchange format/interface
// definition between uses of the index.
struct FlatIndex {
  std::vector<Location> locations;
  std::vector<Entity> entities;
  std::vector<Reference> references;
  std::vector<VirtualMethodLink> virtual_method_links;
};

namespace testing_internal {
// For test use only: Provides access to some private members of the above.
class TestPeer {
 public:
  static void SetSubstituteRelationship(
      Entity& entity, const SubstituteRelationship& relationship) {
    entity.substitute_relationship_ = relationship;
  }
};
}  // namespace testing_internal
}  // namespace indexer
}  // namespace oss_fuzz

#endif  // OSS_FUZZ_INFRA_INDEXER_INDEX_TYPES_H_
