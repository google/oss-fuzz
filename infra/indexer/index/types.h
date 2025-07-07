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
#include <vector>

#include "absl/strings/string_view.h"

namespace oss_fuzz {
namespace indexer {
class InMemoryIndex;

using LocationId = uint64_t;
using EntityId = uint64_t;
using ReferenceId = uint64_t;
constexpr LocationId kInvalidLocationId = 0xffffffffffffffffull;
constexpr EntityId kInvalidEntityId = 0xffffffffffffffffull;

inline bool IsRealPath(absl::string_view path) {
  // Examples of built-in paths: `<built-in>` and `<command-line>`.
  return !path.empty() && !path.starts_with('<');
}

// Represents a source-file location.
// Start and end columns can be set to zero to represent a line-only location.
class Location {
 public:
  Location(absl::string_view path, uint32_t start_line, uint32_t start_column,
           uint32_t end_line, uint32_t end_column);

  inline const std::string& path() const { return path_; }
  inline uint32_t start_line() const { return start_line_; }
  inline uint32_t start_column() const { return start_column_; }
  inline uint32_t end_line() const { return end_line_; }
  inline uint32_t end_column() const { return end_column_; }

  inline bool is_real() const { return IsRealPath(path()); }

 private:
  friend class InMemoryIndex;

  std::string path_;
  uint32_t start_line_;
  uint32_t start_column_;
  uint32_t end_line_;
  uint32_t end_column_;
};

bool operator==(const Location& lhs, const Location& rhs);
// In the comparison, the path and line numbers come before columns.
std::strong_ordering operator<=>(const Location& lhs, const Location& rhs);

template <typename H>
H AbslHashValue(H h, const Location& location) {
  return H::combine(std::move(h), location.path(), location.start_line(),
                    location.start_column(), location.end_line(),
                    location.end_column());
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

  Entity(
      Kind kind, absl::string_view name_prefix, absl::string_view name,
      absl::string_view name_suffix, LocationId location_id,
      bool is_incomplete = false, bool is_weak = false,
      std::optional<EntityId> canonical_entity_id = std::nullopt,
      std::optional<EntityId> implicitly_defined_for_entity_id = std::nullopt,
      std::optional<std::string> enum_value = std::nullopt);

  // Allows to create a copy of `entity` with the ID field values replaced.
  template <class TEntity>
  Entity(TEntity&& entity, LocationId new_location_id,
         std::optional<EntityId> new_canonical_entity_id,
         std::optional<EntityId> new_implicitly_defined_for_entity_id)
      : Entity(std::forward<TEntity>(entity)) {
    location_id_ = new_location_id;
    canonical_entity_id_ = new_canonical_entity_id;
    implicitly_defined_for_entity_id_ = new_implicitly_defined_for_entity_id;
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
  inline std::optional<EntityId> canonical_entity_id() const {
    return canonical_entity_id_;
  }
  inline std::optional<EntityId> implicitly_defined_for_entity_id() const {
    return implicitly_defined_for_entity_id_;
  }
  inline const std::optional<std::string>& enum_value() const {
    return enum_value_;
  }

 private:
  friend class InMemoryIndex;

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

  // Sometimes there are several ways to refer to the same thing,
  // e.g. in the case of looking up a Foo<int> specialization for Foo<T>
  // that hasn't been explicitly provided.
  // In this case we store all the available representations but remember the
  // one to be chosen upon lookups (i.e. Foo<T> will be presented for Foo<int>
  // if there is no explicit specialization).
  std::optional<EntityId> canonical_entity_id_;

  // If this is an entity implicitly defined, but not instantiated from a
  // template (see `canonical_entity_id_`), tracks the relevant explicitly
  // defined entity.
  // Example: The class definition for an implicit constructor / destructor.
  //   Even if the class is a template instantiation, these implicit methods are
  //   defined post-instantiation (as in `FrontendTest.TemplateMemberFn`).
  // Non-example: Implicit `operator==` instantiated from its counterpart
  //   `operator==` implicitly defined in a class template by
  //     const auto operator<=>(...) const = default;
  //   In this case that template `operator==` will be pointed to by
  //   `canonical_entity_id_` and, in turn, will have
  //   `implicitly_defined_for_entity_id_` pointing to the class template. (See
  //   `FrontendTest.ImplicitComparisonInstantiation` for this situation.)
  std::optional<EntityId> implicitly_defined_for_entity_id_;

  // Tracks the decimal value of an enum constant (only for `kEnumConstant`).
  // (A string to support both signed and unsigned 64-bit values - and beyond,
  // like the `__int128` extension.)
  std::optional<std::string> enum_value_;
};

bool operator==(const Entity& lhs, const Entity& rhs);
std::strong_ordering operator<=>(const Entity& lhs, const Entity& rhs);

template <typename H>
H AbslHashValue(H h, const Entity& entity) {
  return H::combine(std::move(h), entity.kind(), entity.is_incomplete(),
                    entity.is_weak(), entity.name(), entity.name_prefix(),
                    entity.name_suffix(), entity.location_id(),
                    entity.canonical_entity_id(),
                    entity.implicitly_defined_for_entity_id());
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

// A simple holder for a sorted index, used as an interchange format/interface
// definition between uses of the index.
struct FlatIndex {
  std::vector<Location> locations;
  std::vector<Entity> entities;
  std::vector<Reference> references;
};
}  // namespace indexer
}  // namespace oss_fuzz

#endif  // OSS_FUZZ_INFRA_INDEXER_INDEX_TYPES_H_
