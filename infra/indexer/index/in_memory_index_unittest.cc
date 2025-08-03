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

#include <cstddef>
#include <cstdio>
#include <filesystem>  // NOLINT
#include <fstream>
#include <optional>
#include <utility>
#include <vector>

#include "indexer/index/file_copier.h"
#include "indexer/index/types.h"
#include "gtest/gtest.h"
#include "absl/log/check.h"
#include "absl/strings/match.h"
#include "absl/types/span.h"

namespace oss_fuzz {
namespace indexer {
namespace {
void PopulateLocationFiles(absl::Span<const Location> locations,
                           const std::filesystem::path& base_path) {
  for (const auto& location : locations) {
    auto path = std::filesystem::path(location.path());
    if (!path.is_absolute()) {
      path = base_path / path;
    }
    std::filesystem::create_directories(path.parent_path());
    std::ofstream tmp_file(path);
    tmp_file << "A";
    CHECK(tmp_file.good());
  }
}

template <typename T>
std::vector<T> EnsureSorted(std::vector<T> items) {
  for (size_t index = 1; index < items.size(); ++index) {
    CHECK(items[index - 1] < items[index]);
  }
  return items;
}

std::vector<Location> GetTestLocations() {
  auto tmp_dir_path = std::filesystem::path(::testing::TempDir());
  // This should return a sorted vector of Locations.
  std::vector<Location> locations = EnsureSorted<Location>({
      // This path is outside base path, and should remain unmodified in the
      // output.
      Location((tmp_dir_path / "last/path.cc").string(), 0, 1),
      Location((tmp_dir_path / "some/file/path.cc").string(), 0, 1),
      Location((tmp_dir_path / "some/file/path.cc").string(), 0, 99),
      Location((tmp_dir_path / "some/other/file/path.cc").string(), 0, 1),
      Location((tmp_dir_path / "some/other/file/path.cc").string(), 0, 99),
  });
  PopulateLocationFiles(locations, tmp_dir_path);
  return locations;
}

std::vector<Entity> GetTestEntities() {
  // This should return a sorted vector of Entities.
  return EnsureSorted<Entity>({
      Entity(Entity::Kind::kVariable, "bar::", "foo", "", 0),
      Entity(Entity::Kind::kEnum, "foo::", "bar", "", 0),
      Entity(Entity::Kind::kVariable, "foo::", "bar", "", 0),
      Entity(Entity::Kind::kVariable, "foo::", "bar", "", 1,
             /*is_incomplete=*/true),
      Entity(Entity::Kind::kFunction, "foo::", "bar", "()", 0),
      Entity(Entity::Kind::kFunction, "foo::", "bar", "(int baz)", 0),
      Entity(Entity::Kind::kEnum, "foo::", "foo", "", 0),
  });
}

std::vector<Reference> GetTestReferences() {
  // This should return a sorted vector of References.
  return EnsureSorted<Reference>({
      Reference(0, 0),
      Reference(0, 1),
      Reference(1, 1),
  });
}

std::vector<Location> GetSecondTestLocations() {
  auto tmp_dir_path = std::filesystem::path(::testing::TempDir());
  // This should return a sorted vector of Locations.
  std::vector<Location> locations = EnsureSorted<Location>({
      // This path is outside base path, and should remain unmodified in the
      // output.
      Location((tmp_dir_path / "aaaa/last/path.cc").string(), 0, 0),
      Location((tmp_dir_path / "aaaa/last/path.cc").string(), 1, 1),
      Location((tmp_dir_path / "bbbb/last/path.cc").string(), 1, 1),
  });
  PopulateLocationFiles(locations, tmp_dir_path);
  return locations;
}

std::vector<Entity> EnsureSubstituteReferenceOrdering(
    std::vector<Entity> entities) {
  for (size_t index = 0; index < entities.size(); ++index) {
    const Entity& entity = entities[index];
    if (entity.substitute_relationship()) {
      CHECK_LT(entity.substitute_relationship()->substitute_entity_id(), index);
    }
  }
  return entities;
}

std::vector<Entity> GetSecondTestEntities() {
  // This should return a sorted vector of Entities whose substitute entity
  // reference IDs are lower than their indices in the vector.
  return EnsureSubstituteReferenceOrdering(EnsureSorted<Entity>({
      Entity(Entity::Kind::kClass, "bar::", "Foo", "<T>", 0),
      Entity(Entity::Kind::kClass, "bar::", "Foo", "<int>", 0,
             /*is_incomplete=*/false, /*is_weak=*/false,
             /*substitute_relationship=*/
             SubstituteRelationship(
                 SubstituteRelationship::Kind::kIsTemplateInstantiationOf, 0)),
      Entity(Entity::Kind::kClass, "jar::", "Bar", "<T>", 0),
      Entity(Entity::Kind::kClass, "jar::", "Bar", "<char>", 0,
             /*is_incomplete=*/false, /*is_weak=*/false,
             /*substitute_relationship=*/
             SubstituteRelationship(
                 SubstituteRelationship::Kind::kIsTemplateInstantiationOf, 2)),
  }));
}

std::vector<Entity> GetThirdTestEntities() {
  // This should return a sorted vector of Entities whose substitute entity
  // reference IDs are lower than their indices in the vector.
  return EnsureSubstituteReferenceOrdering(EnsureSorted<Entity>({
      Entity(Entity::Kind::kEnum, "bar::", "Baz", "", 1),
      Entity(Entity::Kind::kClass, "bar::", "Foo", "<T>", 0),
      Entity(Entity::Kind::kClass, "bar::", "Foo", "<int>", 0,
             /*is_incomplete=*/false, /*is_weak=*/false,
             /*substitute_relationship=*/
             SubstituteRelationship(
                 SubstituteRelationship::Kind::kIsTemplateInstantiationOf, 1)),
      Entity(Entity::Kind::kClass, "jar::", "Bad", "<T>", 0),
      Entity(Entity::Kind::kClass, "jar::", "Bad", "<char>", 0,
             /*is_incomplete=*/false, /*is_weak=*/false,
             /*substitute_relationship=*/
             SubstituteRelationship(
                 SubstituteRelationship::Kind::kIsTemplateInstantiationOf, 3)),
  }));
}
}  // namespace

TEST(InMemoryIndexTest, Locations) {
  FileCopier file_copier("", ::testing::TempDir(), {"/"});
  InMemoryIndex index(file_copier);
  auto locations = GetTestLocations();
  for (const auto& location : locations) {
    index.GetLocationId(location);
  }
  FlatIndex flat_index = std::move(index).Export();
  ASSERT_EQ(flat_index.locations.size(), locations.size());
  for (size_t i = 0; i < flat_index.locations.size(); ++i) {
    ASSERT_EQ(flat_index.locations[i], locations[i]);
  }
}

TEST(InMemoryIndexTest, LocationsBasePath) {
  auto base_path =
      (std::filesystem::path(::testing::TempDir()) / "some").string();
  FileCopier file_copier(base_path, ::testing::TempDir(), {"/"});
  InMemoryIndex index(file_copier);
  auto locations = GetTestLocations();
  for (const auto& location : locations) {
    index.GetLocationId(location);
  }
  FlatIndex flat_index = std::move(index).Export();
  ASSERT_EQ(flat_index.locations.size(), locations.size());
  // The first location is outside the base path, and should be unmodified.
  ASSERT_EQ(flat_index.locations[0], locations[0]);
  for (size_t i = 1; i < flat_index.locations.size(); ++i) {
    // All of the other locations are inside the base path, and should be made
    // into relative paths.
    ASSERT_NE(flat_index.locations[i].path(), locations[i].path());
    ASSERT_EQ(flat_index.locations[i].start_line(), locations[i].start_line());
    ASSERT_EQ(flat_index.locations[i].end_line(), locations[i].end_line());
    ASSERT_TRUE(
        absl::EndsWith(locations[i].path(), flat_index.locations[i].path()));
  }
}

TEST(InMemoryIndexTest, Entities) {
  FileCopier file_copier("", ::testing::TempDir(), {"/"});
  InMemoryIndex index(file_copier);
  auto locations = GetTestLocations();
  auto entities = GetTestEntities();
  for (const auto& location : locations) {
    index.GetLocationId(location);
  }
  for (const auto& entity : entities) {
    index.GetEntityId(entity);
  }
  FlatIndex flat_index = std::move(index).Export();
  ASSERT_EQ(flat_index.entities.size(), entities.size() - 1);
  for (size_t i = 0; i < flat_index.entities.size(); ++i) {
    // There is an incomplete entity in the input, which should be linked out
    // during the index export, so we need to skip over this entry.
    size_t j = i < 3 ? i : i + 1;
    ASSERT_EQ(flat_index.entities[i], entities[j]);
  }
}

TEST(InMemoryIndexTest, SubstituteEntities) {
  FileCopier file_copier("", ::testing::TempDir(), {"/"});
  InMemoryIndex index(file_copier);
  auto locations = GetSecondTestLocations();
  auto entities = GetSecondTestEntities();
  for (const auto& location : locations) {
    index.GetLocationId(location);
  }
  for (const auto& entity : entities) {
    index.GetEntityId(entity);
  }
  FlatIndex flat_index = std::move(index).Export();
  ASSERT_EQ(flat_index.entities.size(), entities.size());
  ASSERT_TRUE(flat_index.entities[1].substitute_relationship().has_value());
  EXPECT_EQ(flat_index.entities[1].substitute_relationship()->kind(),
            SubstituteRelationship::Kind::kIsTemplateInstantiationOf);
  EXPECT_EQ(
      flat_index.entities[1].substitute_relationship()->substitute_entity_id(),
      0);
  ASSERT_TRUE(flat_index.entities[3].substitute_relationship().has_value());
  EXPECT_EQ(flat_index.entities[3].substitute_relationship()->kind(),
            SubstituteRelationship::Kind::kIsTemplateInstantiationOf);
  EXPECT_EQ(
      flat_index.entities[3].substitute_relationship()->substitute_entity_id(),
      2);
}

TEST(InMemoryIndexTest, References) {
  FileCopier file_copier("", ::testing::TempDir(), {"/"});
  InMemoryIndex index(file_copier);
  auto locations = GetTestLocations();
  auto entities = GetTestEntities();
  auto references = GetTestReferences();
  for (const auto& location : locations) {
    index.GetLocationId(location);
  }
  for (const auto& entity : entities) {
    index.GetEntityId(entity);
  }
  for (const auto& reference : references) {
    index.GetReferenceId(reference);
  }
  FlatIndex flat_index = std::move(index).Export();
  ASSERT_EQ(flat_index.references.size(), references.size());
  for (size_t i = 0; i < flat_index.references.size(); ++i) {
    ASSERT_EQ(flat_index.references[i], references[i]);
  }
}

TEST(InMemoryIndexTest, Merge) {
  FileCopier file_copier("", ::testing::TempDir(), {"/"});
  InMemoryIndex index_one(file_copier);
  InMemoryIndex index_two(file_copier);
  auto locations = GetTestLocations();
  auto entities = GetTestEntities();
  auto references = GetTestReferences();
  for (const auto& location : locations) {
    index_one.GetLocationId(location);
    index_two.GetLocationId(location);
  }
  for (size_t i = 0; i < entities.size(); ++i) {
    if (i < 3) {
      index_one.GetEntityId(entities[i]);
    }
    index_two.GetEntityId(entities[i]);
  }
  for (const auto& reference : references) {
    index_one.GetReferenceId(reference);
  }

  {
    // First make sure that merging a single index to an empty index works.
    InMemoryIndex index(file_copier);
    index.Merge(index_one);
    FlatIndex flat_index = std::move(index).Export();
    ASSERT_EQ(flat_index.locations.size(), locations.size());
    ASSERT_EQ(flat_index.entities.size(), 3);
    ASSERT_EQ(flat_index.references.size(), references.size());
  }

  {
    // Now check that merging two different indexes doesn't add duplicate
    // entries.
    InMemoryIndex index(file_copier);
    index.Merge(index_one);
    index.Merge(index_two);
    FlatIndex flat_index = std::move(index).Export();
    ASSERT_EQ(flat_index.locations.size(), locations.size());
    ASSERT_EQ(flat_index.entities.size(), entities.size() - 1);
    ASSERT_EQ(flat_index.references.size(), references.size());
    for (size_t i = 0; i < flat_index.locations.size(); ++i) {
      ASSERT_EQ(flat_index.locations[i], locations[i]);
    }
    for (size_t i = 0; i < flat_index.entities.size(); ++i) {
      size_t j = i < 3 ? i : i + 1;
      ASSERT_EQ(flat_index.entities[i], entities[j]);
    }
    for (size_t i = 0; i < flat_index.references.size(); ++i) {
      ASSERT_EQ(flat_index.references[i], references[i]);
    }
  }
}

TEST(InMemoryIndexTest, MergeWithSubstituteEntities) {
  FileCopier file_copier("", ::testing::TempDir(), {"/"});
  InMemoryIndex index_one(file_copier);
  InMemoryIndex index_two(file_copier);
  auto locations = GetSecondTestLocations();
  auto entities_one = GetSecondTestEntities();
  auto entities_two = GetThirdTestEntities();
  for (const auto& location : locations) {
    index_one.GetLocationId(location);
    index_two.GetLocationId(location);
  }
  for (const auto& entity : entities_one) {
    index_one.GetEntityId(entity);
  }
  for (const auto& entity : entities_two) {
    index_two.GetEntityId(entity);
  }

  {
    // First make sure that merging a single index to an empty index works.
    InMemoryIndex index(file_copier);
    index.Merge(index_one);
    FlatIndex flat_index = std::move(index).Export();
    ASSERT_EQ(flat_index.locations.size(), locations.size());
    ASSERT_EQ(flat_index.entities.size(), entities_one.size());

    EXPECT_EQ(flat_index.entities[0].substitute_relationship(), std::nullopt);
    ASSERT_TRUE(flat_index.entities[1].substitute_relationship().has_value());
    EXPECT_EQ(flat_index.entities[1].substitute_relationship()->kind(),
              SubstituteRelationship::Kind::kIsTemplateInstantiationOf);
    EXPECT_EQ(flat_index.entities[1]
                  .substitute_relationship()
                  ->substitute_entity_id(),
              0);
    EXPECT_EQ(flat_index.entities[2].substitute_relationship(), std::nullopt);
    ASSERT_TRUE(flat_index.entities[3].substitute_relationship().has_value());
    EXPECT_EQ(flat_index.entities[3].substitute_relationship()->kind(),
              SubstituteRelationship::Kind::kIsTemplateInstantiationOf);
    EXPECT_EQ(flat_index.entities[3]
                  .substitute_relationship()
                  ->substitute_entity_id(),
              2);
  }

  {
    // Now check that merging two different indexes doesn't add duplicate
    // entries.
    InMemoryIndex index(file_copier);
    index.Merge(index_one);
    index.Merge(index_two);
    FlatIndex flat_index = std::move(index).Export();
    ASSERT_EQ(flat_index.locations.size(), locations.size());
    ASSERT_EQ(flat_index.entities.size(), 7);
    for (size_t i = 0; i < flat_index.locations.size(); ++i) {
      ASSERT_EQ(flat_index.locations[i], locations[i]);
    }

    ASSERT_EQ(flat_index.entities[0], entities_two[0]);  // bar::Baz
    ASSERT_EQ(flat_index.entities[1], entities_two[1]);  // bar::Foo<T>
    ASSERT_EQ(flat_index.entities[2], entities_two[2]);  // bar::Foo<int>
    ASSERT_EQ(flat_index.entities[3], entities_two[3]);  // jar::Bad<T>
    ASSERT_EQ(flat_index.entities[4], entities_two[4]);  // jar::Bad<char>
    ASSERT_EQ(flat_index.entities[5], entities_one[2]);  // jar::Bar<T>
    const auto& original = entities_one[3];              // jar::Bar<T>
    ASSERT_EQ(
        flat_index.entities[6],
        Entity(
            original.kind(), original.name_prefix(), original.name(),
            original.name_suffix(), original.location_id(),
            original.is_incomplete(), original.is_weak(),
            SubstituteRelationship(
                SubstituteRelationship::Kind::kIsTemplateInstantiationOf, 5)));
  }
}
}  // namespace indexer
}  // namespace oss_fuzz
