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

#include "indexer/index/types.h"

#include <cctype>
#include <compare>
#include <cstdint>
#include <optional>
#include <string>
#include <tuple>

#include "absl/log/check.h"
#include "absl/strings/string_view.h"

namespace oss_fuzz {
namespace indexer {

namespace {

bool IsPositiveDecimalInteger(const char* str) noexcept {
  CHECK_NE(str, nullptr);
  if (*str == '\0') {
    return false;
  }
  for (; *str != '\0'; ++str) {
    if (!isdigit(*str)) {
      return false;
    }
  }
  return true;
}

bool IsDecimalInteger(const char* str) {
  CHECK_NE(str, nullptr);
  if (*str == '-') {
    return IsPositiveDecimalInteger(str + 1);
  }
  return IsPositiveDecimalInteger(str);
}

}  // namespace

Location::Location(absl::string_view path, uint32_t start_line,
                   uint32_t end_line)
    : path_(path), start_line_(start_line), end_line_(end_line) {
  CHECK_LE(start_line, end_line);
}

// This is implicitly used for != in C++20.
bool operator==(const Location& lhs, const Location& rhs) {
  return lhs.path() == rhs.path() && lhs.start_line() == rhs.start_line() &&
         lhs.end_line() == rhs.end_line();
}

// Locations are ordered by file, then start line, then end line.
// This is implicitly used for relational comparisons in C++20 (<, <=, >, >=).
std::strong_ordering operator<=>(const Location& lhs, const Location& rhs) {
  return std::forward_as_tuple(lhs.path(), lhs.start_line(), lhs.end_line()) <=>
         std::forward_as_tuple(rhs.path(), rhs.start_line(), rhs.end_line());
}

Entity::Entity(Kind kind, absl::string_view name_prefix, absl::string_view name,
               absl::string_view name_suffix, LocationId location_id,
               bool is_incomplete, bool is_weak,
               std::optional<SubstituteRelationship> substitute_relationship,
               std::optional<std::string> enum_value,
               VirtualMethodKind virtual_method_kind)
    : kind_(kind),
      is_incomplete_(is_incomplete),
      is_weak_(is_weak),
      name_prefix_(name_prefix),
      name_(name),
      name_suffix_(name_suffix),
      location_id_(location_id),
      substitute_relationship_(substitute_relationship),
      enum_value_(enum_value),
      virtual_method_kind_(virtual_method_kind) {
  CHECK_GT(name.size(), 0);
  CHECK_NE(location_id, kInvalidLocationId);
  if (kind == Kind::kEnumConstant) {
    CHECK(enum_value && IsDecimalInteger(enum_value->c_str()));
  } else {
    CHECK(!enum_value.has_value());
  }
  if (virtual_method_kind != VirtualMethodKind::kNotAVirtualMethod) {
    CHECK(kind == Kind::kFunction);
  }
}

bool operator==(const Entity& lhs, const Entity& rhs) {
  return lhs.kind() == rhs.kind() &&
         lhs.is_incomplete() == rhs.is_incomplete() &&
         lhs.is_weak() == rhs.is_weak() && lhs.name() == rhs.name() &&
         lhs.name_prefix() == rhs.name_prefix() &&
         lhs.name_suffix() == rhs.name_suffix() &&
         lhs.location_id() == rhs.location_id() &&
         lhs.substitute_relationship() == rhs.substitute_relationship() &&
         lhs.enum_value() == rhs.enum_value() &&
         lhs.virtual_method_kind() == rhs.virtual_method_kind();
}

// Entities are sorted by fully-qualified name, then by kind, then by
// completeness, by weakness, and finally by location, substitution
// relationship fields, enum value, and virtual method kind.
std::strong_ordering operator<=>(const Entity& lhs, const Entity& rhs) {
  return std::forward_as_tuple(lhs.name_prefix(), lhs.name(), lhs.name_suffix(),
                               lhs.kind(), lhs.is_incomplete(), lhs.is_weak(),
                               lhs.location_id(), lhs.substitute_relationship(),
                               lhs.enum_value(), lhs.virtual_method_kind()) <=>
         std::forward_as_tuple(rhs.name_prefix(), rhs.name(), rhs.name_suffix(),
                               rhs.kind(), rhs.is_incomplete(), rhs.is_weak(),
                               rhs.location_id(), rhs.substitute_relationship(),
                               rhs.enum_value(), rhs.virtual_method_kind());
}

Reference::Reference(EntityId entity_id, LocationId location_id)
    : entity_id_(entity_id), location_id_(location_id) {
  CHECK_NE(entity_id, kInvalidEntityId);
  CHECK_NE(location_id, kInvalidLocationId);
}

bool operator==(const Reference& lhs, const Reference& rhs) {
  return lhs.entity_id() == rhs.entity_id() &&
         lhs.location_id() == rhs.location_id();
}

// References are sorted by entity then location.
std::strong_ordering operator<=>(const Reference& lhs, const Reference& rhs) {
  return std::forward_as_tuple(lhs.entity_id(), lhs.location_id()) <=>
         std::forward_as_tuple(rhs.entity_id(), rhs.location_id());
}

}  // namespace indexer
}  // namespace oss_fuzz
