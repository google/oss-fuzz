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

#include "indexer/index/in_memory_index.h"

#include <algorithm>
#include <cstddef>
#include <iostream>
#include <optional>
#include <sstream>
#include <string>
#include <utility>
#include <vector>

#include "indexer/index/file_copier.h"
#include "indexer/index/types.h"
#include "absl/container/flat_hash_map.h"
#include "absl/container/flat_hash_set.h"
#include "absl/container/inlined_vector.h"
#include "absl/container/node_hash_map.h"
#include "absl/log/check.h"
#include "absl/log/log.h"
#include "absl/strings/string_view.h"
#include "absl/types/span.h"

namespace oss_fuzz {
namespace indexer {
namespace {

// TODO: record the high-percentile entity counts in typical
// translation units and adjust this accordingly. This should be large enough
// to avoid rehashing during indexing.
const size_t kInitialReservationCount = 0x1000;

bool HasTheSameIdentity(const Entity& lhs, const Entity& rhs) {
  return lhs.kind() == rhs.kind() && lhs.name_prefix() == rhs.name_prefix() &&
         lhs.name() == rhs.name() && lhs.name_suffix() == rhs.name_suffix();
}

void MaybePrintLinkerMessage(absl::Span<const Entity> entities,
                             absl::Span<const Location> locations) {
  std::stringstream stream;

  // First we check the mix of complete and incomplete entities that match this
  // identity.
  size_t complete_count = 0;
  size_t strong_count = 0;
  for (const auto& entity : entities) {
    if (!entity.is_incomplete()) {
      complete_count++;
      if (!entity.is_weak()) strong_count++;
    } else {
      // All complete entities come first.
      break;
    }
  }
  size_t incomplete_count = entities.size() - complete_count;

  // If strong definitions exist, ignore weak ones.
  if (strong_count) complete_count = strong_count;

  // There are two cases where we might want to print a warning message.
  // First, if we have an incomplete entity that shares an identity with
  // multiple complete entities, then we cannot link this correctly.
  // Secondly, if we have an incomplete entity that does not have a
  // corresponding complete entity, then linking will be incomplete.
  if (complete_count > 1 && incomplete_count) {
    stream << "error: multiple definitions for " << entities[0].name_prefix()
           << entities[0].name() << entities[0].name_suffix() << "\n";
  } else if (!complete_count && incomplete_count) {
#ifndef NDEBUG
    // TODO: Enable this in opt builds once the number of warnings is
    // more reasonable.
    stream << "warning: no definition found for " << entities[0].name_prefix()
           << entities[0].name() << entities[0].name_suffix() << "\n";
#else
    return;
#endif  // NDEBUG
  } else {
    return;
  }

  for (const auto& entity : entities) {
    const auto& location = locations[entity.location_id()];
    stream << "  " << location.path() << ":" << location.start_line() << ":"
           << location.end_line()
           << (entity.is_incomplete() ? "" : " [definition]")
           << (entity.is_weak() ? " [weak]" : "") << "\n";
  }
  std::cerr << stream.str();
}

struct ComparePairFirst {
  template <typename T1, typename T2>
  bool operator()(const std::pair<T1, T2>& lhs,
                  const std::pair<T1, T2>& rhs) const {
    return lhs.first < rhs.first;
  }
};

}  // namespace

InMemoryIndex::InMemoryIndex(FileCopier& file_copier)
    : file_copier_(file_copier) {
  Expand(kInitialReservationCount, kInitialReservationCount,
         kInitialReservationCount, kInitialReservationCount,
         kInitialReservationCount, kInitialReservationCount,
         kInitialReservationCount);
}

InMemoryIndex::InMemoryIndex(
    FileCopier& file_copier, const FlatIndex& flat_index,
    const std::vector<std::string>& excluded_tu_absolute_paths)
    : file_copier_(file_copier) {
  absl::flat_hash_set<EntityId> excluded_entity_ids;
  absl::flat_hash_set<ReferenceId> excluded_reference_ids;
  absl::flat_hash_set<TranslationUnitId> excluded_tu_ids;

  if (!excluded_tu_absolute_paths.empty()) {
    CHECK(flat_index.incremental_indexing_metadata.has_value())
        << "Excluding translation units requires incremental indexing metadata";
    const IncrementalIndexingMetadata& incremental_metadata =
        *flat_index.incremental_indexing_metadata;

    absl::flat_hash_set<std::string> excluded_tu_index_paths;
    for (const auto& path : excluded_tu_absolute_paths) {
      excluded_tu_index_paths.insert(file_copier.AbsoluteToIndexPath(path));
    }

    TranslationUnitId tu_id = 0;
    for (const TranslationUnit& tu : incremental_metadata.translation_units) {
      if (excluded_tu_index_paths.contains(tu.index_path())) {
        excluded_tu_ids.insert(tu_id);
      }
      ++tu_id;
    }

    absl::flat_hash_map<EntityId, absl::flat_hash_set<TranslationUnitId>>
        entity_to_tus;
    for (const auto& entity_translation_unit :
         flat_index.incremental_indexing_metadata->entity_translation_units) {
      entity_to_tus[entity_translation_unit.entity_id()].insert(
          entity_translation_unit.tu_id());
    }

    for (const auto& [entity_id, tu_ids] : entity_to_tus) {
      bool all_excluded = true;
      for (const auto& tu_id : tu_ids) {
        if (!excluded_tu_ids.contains(tu_id)) {
          all_excluded = false;
          break;
        }
      }
      if (all_excluded) {
        excluded_entity_ids.insert(entity_id);
      }
    }

    // Check that referenced substitute entities are preserved.
    // This should be guaranteed by the fact that an entity being in an included
    // translation unit implies its substitute entity is also there.
    for (size_t entity_id = 0; entity_id < flat_index.entities.size();
         ++entity_id) {
      if (excluded_entity_ids.contains(entity_id)) {
        continue;
      }
      const Entity& entity = flat_index.entities[entity_id];
      if (entity.substitute_relationship().has_value()) {
        CHECK(!excluded_entity_ids.contains(
            entity.substitute_relationship()->substitute_entity_id()));
      }
    }

    // The same applies to virtual method links.
    for (const VirtualMethodLink& link : flat_index.virtual_method_links) {
      CHECK(!excluded_entity_ids.contains(link.parent()));
      CHECK(!excluded_entity_ids.contains(link.child()));
    }

    // Exclude references to entities that have been excluded.
    for (size_t reference_id = 0; reference_id < flat_index.references.size();
         ++reference_id) {
      if (excluded_entity_ids.contains(
              flat_index.references[reference_id].entity_id())) {
        excluded_reference_ids.insert(reference_id);
      }
    }

    // Exclude references only occurring in the excluded translation units (even
    // if the referenced entities are not excluded).
    absl::flat_hash_map<ReferenceId, absl::flat_hash_set<TranslationUnitId>>
        reference_to_tus;
    for (const auto& reference_translation_unit :
         flat_index.incremental_indexing_metadata
             ->reference_translation_units) {
      reference_to_tus[reference_translation_unit.reference_id()].insert(
          reference_translation_unit.tu_id());
    }

    for (const auto& [reference_id, tu_ids] : reference_to_tus) {
      bool all_excluded = true;
      for (const auto& tu_id : tu_ids) {
        if (!excluded_tu_ids.contains(tu_id)) {
          all_excluded = false;
          break;
        }
      }
      if (all_excluded) {
        excluded_reference_ids.insert(reference_id);
      }
    }
  }

  absl::flat_hash_set<LocationId> locations_to_keep;
  for (size_t entity_id = 0; entity_id < flat_index.entities.size();
       ++entity_id) {
    if (!excluded_entity_ids.contains(entity_id)) {
      locations_to_keep.insert(flat_index.entities[entity_id].location_id());
    }
  }
  for (size_t reference_id = 0; reference_id < flat_index.references.size();
       ++reference_id) {
    if (!excluded_reference_ids.contains(reference_id)) {
      locations_to_keep.insert(
          flat_index.references[reference_id].location_id());
    }
  }

  std::vector<LocationId> new_location_ids(flat_index.locations.size(),
                                           kInvalidLocationId);
  for (size_t location_id = 0; location_id < flat_index.locations.size();
       ++location_id) {
    if (locations_to_keep.contains(location_id)) {
      new_location_ids[location_id] =
          GetIdForLocationWithIndexPath(flat_index.locations[location_id]);
    }
  }

  std::vector<EntityId> new_entity_ids(flat_index.entities.size(),
                                       kInvalidEntityId);
  for (size_t entity_id = 0; entity_id < flat_index.entities.size();
       ++entity_id) {
    if (excluded_entity_ids.contains(entity_id)) {
      continue;
    }
    if (new_entity_ids[entity_id] != kInvalidEntityId) {
      continue;
    }
    absl::InlinedVector<EntityId, 4> entities_to_process;
    EntityId referenced_entity_id = entity_id;
    while (true) {
      entities_to_process.push_back(referenced_entity_id);
      const Entity& entity = flat_index.entities[referenced_entity_id];
      if (entity.substitute_relationship().has_value() &&
          new_entity_ids[entity.substitute_relationship()
                             ->substitute_entity_id()] == kInvalidEntityId) {
        referenced_entity_id =
            entity.substitute_relationship()->substitute_entity_id();
      } else {
        break;
      }
    }

    // Process the substitute entities in reverse order to ensure the referenced
    // entity IDs are ready whenever necessary.
    for (auto it = entities_to_process.rbegin();
         it != entities_to_process.rend(); ++it) {
      const EntityId processed_entity_id = *it;
      const Entity& entity = flat_index.entities[processed_entity_id];
      const LocationId new_location_id = new_location_ids[entity.location_id()];
      const std::optional<EntityId> new_substitute_entity_id =
          entity.substitute_relationship().has_value()
              ? std::optional<EntityId>(
                    new_entity_ids[entity.substitute_relationship()
                                       ->substitute_entity_id()])
              : std::nullopt;
      new_entity_ids[processed_entity_id] = GetEntityId(
          Entity(entity, new_location_id, new_substitute_entity_id));
    }
  }

  std::vector<ReferenceId> new_reference_ids(flat_index.references.size(),
                                             kInvalidReferenceId);
  for (size_t reference_id = 0; reference_id < flat_index.references.size();
       ++reference_id) {
    if (!excluded_reference_ids.contains(reference_id)) {
      const Reference& reference = flat_index.references[reference_id];
      new_reference_ids[reference_id] =
          GetReferenceId({new_entity_ids[reference.entity_id()],
                          new_location_ids[reference.location_id()]});
    }
  }

  for (size_t i = 0; i < flat_index.virtual_method_links.size(); ++i) {
    const VirtualMethodLink& link = flat_index.virtual_method_links[i];
    if (!excluded_entity_ids.contains(link.parent()) &&
        !excluded_entity_ids.contains(link.child())) {
      GetVirtualMethodLinkId(
          {new_entity_ids[link.parent()], new_entity_ids[link.child()]});
    }
  }

  if (flat_index.incremental_indexing_metadata.has_value()) {
    const auto& metadata = *flat_index.incremental_indexing_metadata;
    std::vector<TranslationUnitId> new_tu_ids(metadata.translation_units.size(),
                                              kInvalidTranslationUnitId);
    for (size_t tu_id = 0; tu_id < metadata.translation_units.size(); ++tu_id) {
      if (excluded_tu_ids.contains(tu_id)) {
        continue;
      }
      new_tu_ids[tu_id] =
          GetTranslationUnitId(metadata.translation_units[tu_id]);
    }
    for (const auto& entity_translation_unit :
         metadata.entity_translation_units) {
      if (excluded_tu_ids.contains(entity_translation_unit.tu_id())) {
        continue;
      }
      AddEntityTranslationUnit(
          {new_entity_ids[entity_translation_unit.entity_id()],
           new_tu_ids[entity_translation_unit.tu_id()]});
    }
    for (const auto& reference_translation_unit :
         metadata.reference_translation_units) {
      if (excluded_tu_ids.contains(reference_translation_unit.tu_id())) {
        continue;
      }
      AddReferenceTranslationUnit(
          {new_reference_ids[reference_translation_unit.reference_id()],
           new_tu_ids[reference_translation_unit.tu_id()]});
    }
  }
}

InMemoryIndex::~InMemoryIndex() = default;

void InMemoryIndex::Merge(const InMemoryIndex& other) {
  // This is guaranteed to be large enough to avoid another rehash for the rest
  // of this merge operation. This may be a larger reservation than we need; but
  // this is not an issue, since we almost always use the same indexes to merge
  // into, so the overly-large reservation will be used later.
  Expand(other.locations_.size(), other.entities_.size(),
         other.references_.size(), other.virtual_method_links_.size(),
         other.translation_units_.size(),
         other.entity_translation_units_.size(),
         other.reference_translation_units_.size());

  std::vector<LocationId> new_location_ids(other.locations_.size(),
                                           kInvalidLocationId);
  for (const auto& [location, id] : other.locations_) {
    new_location_ids[id] = GetIdForLocationWithIndexPath(location);
  }

  // We need to update the location_id for entities, the entity_id and
  // location_id for references, and parent/child entity ids for virtual method
  // links during insertion.

  // Entity references point to entities with lower ids. Process them
  // in the increasing order of old ids to ensure reference resolution.
  using EntitiesIterator = decltype(other.entities_)::const_iterator;
  std::vector<std::optional<EntitiesIterator>> other_entities(
      other.entities_.size());
  for (auto it = other.entities_.cbegin(); it != other.entities_.cend(); ++it) {
    const EntityId old_id = it->second;
    CHECK(old_id < other_entities.size() && !other_entities[old_id]);
    other_entities[old_id] = it;
  }
  std::vector<EntityId> new_entity_ids(other.entities_.size(),
                                       kInvalidEntityId);
  std::vector<std::optional<SubstituteRelationship::Kind>>
      substitute_relationships(other.entities_.size());
  for (const auto& optional_iter : other_entities) {
    // The fact that the CHECK above was satisfied `other_entities.size()` times
    // means that all the `other_entities` items have values.
    CHECK(optional_iter);
    const auto& iter = *optional_iter;
    const Entity& entity = iter->first;
    const EntityId id = iter->second;
    std::optional<EntityId> new_substitute_entity_id;
    if (entity.substitute_relationship()) {
      const EntityId old_substitute_entity_id =
          entity.substitute_relationship()->substitute_entity_id();
      CHECK_LT(old_substitute_entity_id, id);
      new_substitute_entity_id = new_entity_ids[old_substitute_entity_id];
      CHECK_NE(*new_substitute_entity_id, kInvalidEntityId);
    }
    const EntityId new_id = GetEntityId(Entity(
        entity, /*new_location_id=*/new_location_ids[entity.location_id()],
        new_substitute_entity_id));
    new_entity_ids[id] = new_id;
  }

  std::vector<ReferenceId> new_reference_ids(other.references_.size(),
                                             kInvalidReferenceId);
  for (const auto& [reference, id] : other.references_) {
    new_reference_ids[id] =
        GetReferenceId({new_entity_ids[reference.entity_id()],
                        new_location_ids[reference.location_id()]});
  }

  for (const auto& [link, id] : other.virtual_method_links_) {
    GetVirtualMethodLinkId(
        {new_entity_ids[link.parent()], new_entity_ids[link.child()]});
  }

  std::vector<TranslationUnitId> new_translation_unit_ids(
      other.translation_units_.size(), kInvalidEntityId);
  for (const auto& [tu, id] : other.translation_units_) {
    new_translation_unit_ids[id] = GetTranslationUnitId(tu);
  }

  for (const auto& entity_translation_unit : other.entity_translation_units_) {
    AddEntityTranslationUnit(
        {new_entity_ids[entity_translation_unit.entity_id()],
         new_translation_unit_ids[entity_translation_unit.tu_id()]});
  }

  for (const auto& reference_translation_unit :
       other.reference_translation_units_) {
    AddReferenceTranslationUnit(
        {new_reference_ids[reference_translation_unit.reference_id()],
         new_translation_unit_ids[reference_translation_unit.tu_id()]});
  }
}

void InMemoryIndex::Expand(size_t locations_count, size_t entities_count,
                           size_t references_count,
                           size_t virtual_method_links_count,
                           size_t translation_units_count,
                           size_t entity_translation_units_count,
                           size_t reference_translation_units_count) {
  locations_.reserve(locations_.size() + locations_count);
  entities_.reserve(entities_.size() + entities_count);
  references_.reserve(references_.size() + references_count);
  virtual_method_links_.reserve(virtual_method_links_.size() +
                                virtual_method_links_count);
  translation_units_.reserve(translation_units_.size() +
                             translation_units_count);
  entity_translation_units_.reserve(entity_translation_units_.size() +
                                    entity_translation_units_count);
  reference_translation_units_.reserve(reference_translation_units_.size() +
                                       reference_translation_units_count);
}

void InMemoryIndex::SetTranslationUnit(absl::string_view absolute_path) {
  const std::string index_path =
      file_copier_.AbsoluteToIndexPath(absolute_path);
  current_translation_unit_id_ =
      GetTranslationUnitId(TranslationUnit(index_path));
}

LocationId InMemoryIndex::GetLocationId(Location location) {
  if (location.is_real()) {
    // Adjust paths within the base_path to be relative paths.
    location.path_ = file_copier_.AbsoluteToIndexPath(location.path());
  }
  return GetIdForLocationWithIndexPath(location);
}

LocationId InMemoryIndex::GetIdForLocationWithIndexPath(
    const Location& location) {
  auto [iter, inserted] = locations_.insert({location, next_location_id_});
  if (inserted) {
    next_location_id_++;
    if (location.is_real()) {
      file_copier_.RegisterIndexedFile(location.path());
    }
  }

  return iter->second;
}

EntityId InMemoryIndex::GetEntityId(const Entity& entity) {
  // If an entity and its substitute have identical renderings and are thus
  // indistinguishable during index merging, prevent creating self-references
  // due to this collapse by pre-merging them here already.
  if (entity.substitute_relationship()) {
    const EntityId substitute_entity_id =
        entity.substitute_relationship()->substitute_entity_id();
    const Entity& substitute_entity = GetEntityById(substitute_entity_id);
    if (HasTheSameIdentity(substitute_entity, entity)) {
      return substitute_entity_id;
    }
  }

  auto [iter, inserted] = entities_.insert({entity, next_entity_id_});
  const EntityId entity_id = iter->second;
  if (inserted) {
    next_entity_id_++;
    id_to_entity_.push_back(&iter->first);
    if (auto relationship = entity.substitute_relationship_) {
      CHECK_LT(relationship->substitute_entity_id(), entity_id);
    }
  }

  if (current_translation_unit_id_ != kInvalidTranslationUnitId) {
    AddEntityTranslationUnit({entity_id, current_translation_unit_id_});
  }

  return entity_id;
}

EntityId InMemoryIndex::GetExistingEntityId(const Entity& entity) const {
  auto it = entities_.find(entity);
  if (it == entities_.end()) {
    return kInvalidEntityId;
  }
  return it->second;
}

const Entity& InMemoryIndex::GetEntityById(EntityId entity_id) const {
  CHECK_NE(entity_id, kInvalidEntityId);
  CHECK_LT(entity_id, id_to_entity_.size());
  return *id_to_entity_[entity_id];
}

ReferenceId InMemoryIndex::GetReferenceId(const Reference& reference) {
  auto [iter, inserted] = references_.insert({reference, next_reference_id_});
  if (inserted) {
    next_reference_id_++;
  }
  const ReferenceId reference_id = iter->second;

  if (current_translation_unit_id_ != kInvalidTranslationUnitId) {
    AddReferenceTranslationUnit({reference_id, current_translation_unit_id_});
  }

  return reference_id;
}

VirtualMethodLinkId InMemoryIndex::GetVirtualMethodLinkId(
    const VirtualMethodLink& link) {
  auto [iter, inserted] =
      virtual_method_links_.insert({link, next_virtual_method_link_id_});
  if (inserted) {
    next_virtual_method_link_id_++;
  }
  return iter->second;
}

TranslationUnitId InMemoryIndex::GetTranslationUnitId(
    const TranslationUnit& tu) {
  auto [iter, inserted] =
      translation_units_.insert({tu, next_translation_unit_id_});
  if (inserted) {
    next_translation_unit_id_++;
  }
  return iter->second;
}

void InMemoryIndex::AddEntityTranslationUnit(
    const EntityTranslationUnit& entity_translation_unit) {
  entity_translation_units_.insert(entity_translation_unit);
}

void InMemoryIndex::AddReferenceTranslationUnit(
    const ReferenceTranslationUnit& reference_translation_unit) {
  reference_translation_units_.insert(reference_translation_unit);
}

FlatIndex InMemoryIndex::Export() && {
  FlatIndex result;

  // Order is important here, since until we've sorted Locations we don't have
  // a fixed order for Entities, and similarly until both the Entities and
  // Locations are sorted the order of the References is still being updated.

  std::vector<LocationId> new_location_ids(locations_.size(),
                                           kInvalidLocationId);
  {
    // First sort the locations in pairs with their original id.
    std::vector<std::pair<Location, LocationId>> sorted_locations;
    for (const auto& [location, id] : locations_) {
      sorted_locations.emplace_back(location, id);
    }
    std::sort(sorted_locations.begin(), sorted_locations.end(),
              ComparePairFirst());
    CHECK_EQ(sorted_locations.size(), locations_.size());
    locations_.clear();

    // Now iterate through the sorted locations, building a lookup from the old
    // to the new sorted ids, and building the results vector.
    result.locations.reserve(sorted_locations.size());
    LocationId new_id = 0;
    for (auto& [location, old_id] : sorted_locations) {
      result.locations.emplace_back(/*path=*/std::move(location.path_),
                                    /*start_line=*/location.start_line(),
                                    /*end_line=*/location.end_line());
      new_location_ids[old_id] = new_id++;
    }
  }

  std::vector<EntityId> new_entity_ids(entities_.size(), kInvalidEntityId);
  {
    // Repeat for entities, but updating stale location ids.
    std::vector<std::pair<Entity, EntityId>> sorted_entities;
    for (const auto& [entity, id] : entities_) {
      const LocationId old_location_id = entity.location_id();
      LocationId new_location_id = new_location_ids[old_location_id];
      CHECK_NE(new_location_id, kInvalidLocationId);

      if (entity.substitute_relationship()) {
        CHECK_LT(entity.substitute_relationship()->substitute_entity_id(), id);
      }

      sorted_entities.emplace_back(entity, id);
      Entity& new_entity = sorted_entities.back().first;
      new_entity.location_id_ = new_location_id;
    }
    std::sort(sorted_entities.begin(), sorted_entities.end(),
              ComparePairFirst());
    CHECK_EQ(sorted_entities.size(), entities_.size());
    entities_.clear();
    id_to_entity_.clear();

    // Now iterate through the sorted entities, building a lookup from the old
    // to the new sorted ids, and building the results vector. Since entities
    // are sorted by name, then by type, then by completeness and weakness (and
    // finally by location), we can perform linking at this stage to remove
    // incomplete entities where possible and get rid of overridden weak
    // symbols.
    result.entities.reserve(sorted_entities.size());
    EntityId new_id = kInvalidEntityId;
    std::vector<Entity> same_entities;
    for (auto& [entity, old_id] : sorted_entities) {
      if (!same_entities.empty() &&
          HasTheSameIdentity(entity, same_entities[0])) {
        same_entities.emplace_back(entity);
        if (!entity.is_incomplete() && !entity.is_weak()) {
          result.entities.emplace_back(std::move(entity));
          ++new_id;
        }
      } else {
        MaybePrintLinkerMessage(same_entities, result.locations);
        same_entities = {entity};
        result.entities.emplace_back(std::move(entity));
        ++new_id;
      }

      new_entity_ids[old_id] = new_id;
    }
    MaybePrintLinkerMessage(same_entities, result.locations);
    CHECK_EQ(new_entity_ids.size(), sorted_entities.size());
    CHECK_LE(result.entities.size(), sorted_entities.size());

    // Update the substitute entity ids.
    for (Entity& entity : result.entities) {
      if (entity.substitute_relationship()) {
        entity.substitute_relationship_->entity_id_ =
            new_entity_ids[entity.substitute_relationship_->entity_id_];
      }
    }
  }

  // Maintain old-to-new reference ids for the case of reference-TU pairs below.
  std::vector<ReferenceId> new_reference_ids(references_.size(),
                                             kInvalidReferenceId);
  {
    std::vector<std::pair<Reference, ReferenceId>> sorted_references;
    for (const auto& [reference, id] : references_) {
      EntityId new_entity_id = new_entity_ids[reference.entity_id()];
      CHECK_NE(new_entity_id, kInvalidEntityId);
      LocationId new_location_id = new_location_ids[reference.location_id()];
      CHECK_NE(new_location_id, kInvalidLocationId);
      sorted_references.emplace_back(Reference(new_entity_id, new_location_id),
                                     id);
    }
    std::sort(sorted_references.begin(), sorted_references.end(),
              ComparePairFirst());
    CHECK_EQ(sorted_references.size(), references_.size());
    references_.clear();

    result.references.reserve(references_.size());
    ReferenceId new_id = 0;
    for (auto& [reference, old_id] : sorted_references) {
      // Avoid duplicate references that may have arisen from entity linkage.
      if (!result.references.empty() && result.references.back() == reference) {
        new_reference_ids[old_id] = new_id - 1;
      } else {
        result.references.emplace_back(reference);
        new_reference_ids[old_id] = new_id++;
      }
    }
  }

  // We don't have to maintain the old-to-new link id mapping.
  result.virtual_method_links.reserve(virtual_method_links_.size());
  for (const auto& [link, id] : virtual_method_links_) {
    EntityId new_parent = new_entity_ids[link.parent()];
    CHECK_NE(new_parent, kInvalidEntityId);
    EntityId new_child = new_entity_ids[link.child()];
    CHECK_NE(new_child, kInvalidEntityId);
    result.virtual_method_links.emplace_back(new_parent, new_child);
  }
  std::sort(result.virtual_method_links.begin(),
            result.virtual_method_links.end());

  if (!translation_units_.empty()) {
    auto& metadata = result.incremental_indexing_metadata.emplace();

    std::vector<TranslationUnitId> new_translation_unit_ids(
        translation_units_.size(), kInvalidEntityId);
    {
      std::vector<std::pair<TranslationUnit, TranslationUnitId>> sorted_tus;
      for (const auto& [tu, id] : translation_units_) {
        sorted_tus.emplace_back(tu, id);
      }
      std::sort(sorted_tus.begin(), sorted_tus.end(), ComparePairFirst());
      CHECK_EQ(sorted_tus.size(), translation_units_.size());
      translation_units_.clear();

      metadata.translation_units.reserve(sorted_tus.size());
      TranslationUnitId new_id = 0;
      for (auto& [tu, old_id] : sorted_tus) {
        metadata.translation_units.emplace_back(tu);
        new_translation_unit_ids[old_id] = new_id++;
      }
    }

    metadata.entity_translation_units.reserve(entity_translation_units_.size());
    for (const auto& entity_translation_unit : entity_translation_units_) {
      EntityId new_entity_id =
          new_entity_ids[entity_translation_unit.entity_id()];
      CHECK_NE(new_entity_id, kInvalidEntityId);
      TranslationUnitId new_tu_id =
          new_translation_unit_ids[entity_translation_unit.tu_id()];
      CHECK_NE(new_tu_id, kInvalidTranslationUnitId);
      metadata.entity_translation_units.emplace_back(new_entity_id, new_tu_id);
    }
    std::sort(metadata.entity_translation_units.begin(),
              metadata.entity_translation_units.end());
    // Remove duplicate entity-TU pairs that may have arisen from entity
    // linkage.
    metadata.entity_translation_units.erase(
        std::unique(metadata.entity_translation_units.begin(),
                    metadata.entity_translation_units.end()),
        metadata.entity_translation_units.end());

    metadata.reference_translation_units.reserve(
        reference_translation_units_.size());
    for (const auto& reference_translation_unit :
         reference_translation_units_) {
      ReferenceId new_reference_id =
          new_reference_ids[reference_translation_unit.reference_id()];
      CHECK_NE(new_reference_id, kInvalidReferenceId);
      TranslationUnitId new_tu_id =
          new_translation_unit_ids[reference_translation_unit.tu_id()];
      CHECK_NE(new_tu_id, kInvalidTranslationUnitId);
      metadata.reference_translation_units.emplace_back(new_reference_id,
                                                        new_tu_id);
    }
    std::sort(metadata.reference_translation_units.begin(),
              metadata.reference_translation_units.end());
    // Remove duplicate reference-TU pairs that may have arisen from entity
    // linkage.
    metadata.reference_translation_units.erase(
        std::unique(metadata.reference_translation_units.begin(),
                    metadata.reference_translation_units.end()),
        metadata.reference_translation_units.end());
  }

  return result;
}

}  // namespace indexer
}  // namespace oss_fuzz
