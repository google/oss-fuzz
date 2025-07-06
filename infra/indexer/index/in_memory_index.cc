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
#include "absl/log/check.h"
#include "absl/log/log.h"
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

template <class Item, typename ItemId>
class Accessor {
 public:
  virtual ~Accessor() = default;
  virtual const Item& GetById(ItemId) const = 0;
};

template <class Item, typename ItemId>
class HashAccessor : public Accessor<Item, ItemId> {
 public:
  explicit HashAccessor(const absl::flat_hash_map<Item, ItemId>& items)
      : items_(items) {}
  const Item& GetById(ItemId id) const override {
    for (const auto& [item, item_id] : items_) {
      if (item_id == id) {
        return item;
      }
    }
    LOG(FATAL) << "Couldn't find an item by ID";
  }

 private:
  const absl::flat_hash_map<Item, ItemId>& items_;
};

template <class Item, typename ItemId>
class VectorAccessor : public Accessor<Item, ItemId> {
 public:
  explicit VectorAccessor(const std::vector<Item>& items) : items_(items) {}
  const Item& GetById(ItemId id) const override {
    CHECK_LT(id, items_.size());
    return items_[id];
  }

 private:
  const std::vector<Item>& items_;
};

void ReportEntity(std::ostream& os, const Entity& entity,
                  const Accessor<Entity, EntityId>& entities,
                  const Accessor<Location, LocationId>& locations,
                  int depth = 1) {
  if (depth > 5) {
    os << "...chain continues (a cycle?)...";
    return;
  }
  for (int i = 0; i < depth; ++i) {
    os << "  ";
  }
  const Location& entity_location = locations.GetById(entity.location_id());
  os << entity.full_name() << " at " << entity_location.path() << ":"
     << entity_location.start_line() << "-" << entity_location.end_line()
     << "\n";
  if (entity.canonical_entity_id().has_value()) {
    const Entity& canonical_entity =
        entities.GetById(*entity.canonical_entity_id());
    ReportEntity(os, canonical_entity, entities, locations, depth + 1);
  }
}

void ReportCanonicalChain(const Entity& entity,
                          const Accessor<Entity, EntityId>& entities,
                          const Accessor<Location, LocationId>& locations) {
  std::stringstream stream;
  stream << "Unexpected canonical entity reference chain for:\n";
  ReportEntity(stream, entity, entities, locations);
  stream << "(Please report the above as a bug marked 'CHAIN'.)\n";
  std::cerr << stream.str();
}
}  // namespace

InMemoryIndex::InMemoryIndex(FileCopier& file_copier)
    : file_copier_(file_copier) {
  Expand(kInitialReservationCount, kInitialReservationCount,
         kInitialReservationCount);
}

InMemoryIndex::~InMemoryIndex() = default;

void InMemoryIndex::Merge(const InMemoryIndex& other) {
  // This is guaranteed to be large enough to avoid another rehash for the rest
  // of this merge operation. This may be a larger reservation than we need; but
  // this is not an issue, since we almost always use the same indexes to merge
  // into, so the overly-large reservation will be used later.
  Expand(other.locations_.size(), other.entities_.size(),
         other.references_.size());

  std::vector<LocationId> new_location_ids(other.locations_.size(),
                                           kInvalidLocationId);
  for (const auto& [location, id] : other.locations_) {
    new_location_ids[id] = GetLocationId(location);
  }

  // We need to update the location_id for entities, and the entity_id and
  // location_id for references during insertion.

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
  // For an old entity ID, stores the new ID of its canonical entity.
  std::vector<EntityId> new_canonical_entity_ids(other.entities_.size(),
                                                 kInvalidEntityId);
  for (const auto& optional_iter : other_entities) {
    // The fact that the CHECK above was satisfied `other_entities.size()` times
    // means that all the `other_entities` items have values.
    CHECK(optional_iter);
    const auto& iter = *optional_iter;
    const Entity& entity = iter->first;
    const EntityId id = iter->second;
    std::optional<EntityId> canonical_entity_id = std::nullopt;
    if (entity.canonical_entity_id()) {
      const EntityId old_canonical_entity_id = *entity.canonical_entity_id();
      CHECK_LT(old_canonical_entity_id, id);
      // If the canonical entity for `entity` has a canonical reference in turn,
      // this is an (undesired) canonical reference chain.
      if (new_canonical_entity_ids[old_canonical_entity_id] !=
          kInvalidEntityId) {
        ReportCanonicalChain(
            entity, HashAccessor<Entity, EntityId>(other.entities_),
            HashAccessor<Location, LocationId>(other.locations_));
        // Reduce the chain to its ultimate canonical entity.
        canonical_entity_id = new_canonical_entity_ids[old_canonical_entity_id];
      } else {
        canonical_entity_id = new_entity_ids[old_canonical_entity_id];
      }
      CHECK_NE(*canonical_entity_id, kInvalidEntityId);
    }
    std::optional<EntityId> implicitly_defined_for_entity_id = std::nullopt;
    if (entity.implicitly_defined_for_entity_id()) {
      const EntityId old_implicitly_defined_for_entity_id =
          *entity.implicitly_defined_for_entity_id();
      CHECK_LT(old_implicitly_defined_for_entity_id, id);
      implicitly_defined_for_entity_id =
          new_entity_ids[old_implicitly_defined_for_entity_id];
    }
    const EntityId new_id = GetEntityId(Entity(
        entity, /*new_location_id=*/new_location_ids[entity.location_id()],
        /*new_canonical_entity_id=*/canonical_entity_id,
        /*new_implicitly_defined_for_entity_id=*/
        implicitly_defined_for_entity_id));

    new_entity_ids[id] = new_id;
    if (canonical_entity_id) {
      CHECK_LT(*canonical_entity_id, new_id);
      new_canonical_entity_ids[id] = *canonical_entity_id;
    }
  }

  for (const auto& [reference, id] : other.references_) {
    GetReferenceId({new_entity_ids[reference.entity_id()],
                    new_location_ids[reference.location_id()]});
  }
}

void InMemoryIndex::Expand(size_t locations_count, size_t entities_count,
                           size_t references_count) {
  locations_.reserve(locations_.size() + locations_count);
  entities_.reserve(entities_.size() + entities_count);
  references_.reserve(references_.size() + references_count);
}

LocationId InMemoryIndex::GetLocationId(const Location& location) {
  // Adjust paths within the base_path to be relative paths.
  Location new_location = location;
  new_location.path_ = file_copier_.ToIndexPath(location.path());

  auto [iter, inserted] = locations_.insert({new_location, next_location_id_});
  if (inserted) {
    next_location_id_++;
    file_copier_.RegisterIndexedFile(new_location.path());
  }

  return iter->second;
}

EntityId InMemoryIndex::GetEntityId(const Entity& entity) {
  auto [iter, inserted] = entities_.insert({entity, next_entity_id_});
  if (inserted) {
    next_entity_id_++;
  }
  const EntityId entity_id = iter->second;
  if (entity.canonical_entity_id()) {
    CHECK_LT(*entity.canonical_entity_id(), entity_id);
  }
  if (entity.implicitly_defined_for_entity_id()) {
    CHECK_LT(*entity.implicitly_defined_for_entity_id(), entity_id);
  }
  return entity_id;
}

ReferenceId InMemoryIndex::GetReferenceId(const Reference& reference) {
  auto [iter, inserted] = references_.insert({reference, next_reference_id_});
  if (inserted) {
    next_reference_id_++;
  }
  return iter->second;
}

FlatIndex InMemoryIndex::Export(bool store_canonical_entities) {
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
    //
    // Compress the locations by removing the column information.
    // The comparison defined on `Location` makes sure locations with the same
    // line ranges end up together so that we can deduplicate them on the fly.
    result.locations.reserve(sorted_locations.size());
    LocationId new_id = 0;
    const Location* previous_location = nullptr;
    LocationId last_id = kInvalidLocationId;
    for (auto& [location, old_id] : sorted_locations) {
      if (previous_location == nullptr ||
          previous_location->path() != location.path() ||
          previous_location->start_line() != location.start_line() ||
          previous_location->end_line() != location.end_line()) {
        result.locations.emplace_back(/*path=*/std::move(location.path_),
                                      /*start_line=*/location.start_line(),
                                      /*start_column=*/0,
                                      /*end_line=*/location.end_line(),
                                      /*end_column=*/0);
        last_id = new_id++;
      }
      CHECK_NE(last_id, kInvalidLocationId);
      new_location_ids[old_id] = last_id;
      previous_location = &location;
    }
  }

  std::vector<LocationId> new_entity_ids(entities_.size(), kInvalidEntityId);
  {
    // Repeat for entities, but updating stale location ids.
    std::vector<std::pair<Entity, EntityId>> sorted_entities;
    for (const auto& [entity, id] : entities_) {
      const LocationId old_location_id = entity.location_id();
      LocationId new_location_id = new_location_ids[old_location_id];
      CHECK_NE(new_location_id, kInvalidLocationId);

      if (entity.canonical_entity_id()) {
        CHECK_LT(*entity.canonical_entity_id(), id);
      }

      auto& iter = sorted_entities.emplace_back(entity, id);
      Entity& new_entity = iter.first;
      new_entity.location_id_ = new_location_id;
    }
    std::sort(sorted_entities.begin(), sorted_entities.end(),
              ComparePairFirst());
    CHECK_EQ(sorted_entities.size(), entities_.size());
    entities_.clear();

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

    // Update the implicit-for entity ids.
    for (Entity& entity : result.entities) {
      if (entity.implicitly_defined_for_entity_id()) {
        entity.implicitly_defined_for_entity_id_ =
            new_entity_ids[*entity.implicitly_defined_for_entity_id()];
      }
    }

    if (store_canonical_entities) {
      // Update the canonical entity ids.
      for (Entity& entity : result.entities) {
        if (entity.canonical_entity_id()) {
          entity.canonical_entity_id_ =
              new_entity_ids[*entity.canonical_entity_id()];
        }
      }
      // Before the reordering, an entity's canonical entity id, if present, was
      // guaranteed to be lower than that of the entity itself. Thus processing
      // the entities in the order of ascending old ids gives a topological
      // ordering with respect to canonical references.
      for (EntityId id : new_entity_ids) {
        Entity& entity = result.entities[id];
        if (entity.canonical_entity_id() &&
            result.entities[*entity.canonical_entity_id()]
                .canonical_entity_id()) {
          ReportCanonicalChain(
              entity, VectorAccessor<Entity, EntityId>(result.entities),
              VectorAccessor<Location, LocationId>(result.locations));
          entity.canonical_entity_id_ =
              result.entities[*entity.canonical_entity_id()]
                  .canonical_entity_id();
        }
      }
    } else {
      for (auto& entity : result.entities) {
        entity.canonical_entity_id_ = std::nullopt;
      }
    }
  }

  // Here we don't need to maintain a mapping from the old to the new reference
  // ids.
  result.references.reserve(references_.size());
  for (const auto& [reference, id] : references_) {
    EntityId new_entity_id = new_entity_ids[reference.entity_id()];
    CHECK_NE(new_entity_id, kInvalidEntityId);
    LocationId new_location_id = new_location_ids[reference.location_id()];
    CHECK_NE(new_location_id, kInvalidLocationId);
    result.references.emplace_back(new_entity_id, new_location_id);
  }
  std::sort(result.references.begin(), result.references.end());
  // Remove duplicates that could have arisen due to location column erasure.
  auto last = std::unique(result.references.begin(), result.references.end());
  result.references.erase(last, result.references.end());

  return result;
}

}  // namespace indexer
}  // namespace oss_fuzz
