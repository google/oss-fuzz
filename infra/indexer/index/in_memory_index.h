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

#ifndef OSS_FUZZ_INFRA_INDEXER_INDEX_IN_MEMORY_INDEX_H_
#define OSS_FUZZ_INFRA_INDEXER_INDEX_IN_MEMORY_INDEX_H_

#include <cstddef>
#include <vector>

#include "indexer/index/file_copier.h"
#include "indexer/index/types.h"
#include "absl/container/flat_hash_map.h"
#include "absl/container/node_hash_map.h"

namespace oss_fuzz {
namespace indexer {
// InMemoryIndex is a space-inefficient index structure that allows for fast
// insertion and lookup. This is the main data-structure used for index storage
// while building the index, and it supports both adding single entries to the
// index and efficiently merging multiple indexes together.
class InMemoryIndex {
 public:
  // `base_path` is the filesystem path of the main source root for the project
  // being indexed. Paths within `base_path` will be expressed as relative paths
  // in the index.
  explicit InMemoryIndex(FileCopier& file_copier);

  ~InMemoryIndex();

  void Merge(const InMemoryIndex& other);

  // Ensures that there is sufficient additional storage to add at least
  // `locations_count` new unique locations, `entities_count` new unique
  // entities, ...
  void Expand(size_t locations_count, size_t entities_count,
              size_t references_count, size_t virtual_method_links_count);

  // The `GetXxxId` functions return the id of an existing, matching object if
  // there is already one in the index, or allocate a new id if there is not an
  // identical object in the index.
  // `GetLocationId` expects a location with an absolute path if not built-in;
  // use `ToNormalizedAbsolutePath` to obtain one.
  LocationId GetLocationId(Location location);
  EntityId GetEntityId(const Entity& entity);
  const Entity& GetEntityById(EntityId entity_id) const;
  ReferenceId GetReferenceId(const Reference& reference);
  VirtualMethodLinkId GetVirtualMethodLinkId(const VirtualMethodLink& link);

  // In contrast, `GetExistingEntityId` returns `kInvalidEntityId` if such an
  // entity has not been passed to `GetEntityId` before.
  EntityId GetExistingEntityId(const Entity& entity) const;

  // Build a sorted FlatIndex from the contents of this index. This invalidates
  // the contents of this InMemoryIndex, which should no longer be used.
  // Usage:
  //   FlatIndex& flat_index = std::move(index).Export();
  FlatIndex Export() &&;

 private:
  FileCopier& file_copier_;

  // Like `GetLocationId`, but requires the path to be already index-adjusted.
  LocationId GetIdForLocationWithIndexPath(const Location& location);

  // Although we could sort location_lookup_ in advance, the performance impact
  // on indexing if we use a btree_map is significant, and it's much faster
  // to sort the index at the end.
  LocationId next_location_id_ = 0;
  absl::flat_hash_map<Location, LocationId> locations_;

  EntityId next_entity_id_ = 0;
  // Pointer stability is needed for `id_to_entity_`.
  absl::node_hash_map<Entity, EntityId> entities_;
  // Maps back from the entity ID to an entity in `entities_`.
  std::vector<const Entity*> id_to_entity_;

  ReferenceId next_reference_id_ = 0;
  absl::flat_hash_map<Reference, ReferenceId> references_;

  VirtualMethodLinkId next_virtual_method_link_id_ = 0;
  absl::flat_hash_map<VirtualMethodLink, VirtualMethodLinkId>
      virtual_method_links_;
};

}  // namespace indexer
}  // namespace oss_fuzz

#endif  // OSS_FUZZ_INFRA_INDEXER_INDEX_IN_MEMORY_INDEX_H_
