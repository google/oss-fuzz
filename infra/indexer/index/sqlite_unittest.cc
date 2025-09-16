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

#include "indexer/index/sqlite.h"

#include <filesystem>  // NOLINT
#include <optional>
#include <string>

#include "indexer/index/types.h"
#include "gmock/gmock.h"
#include "gtest/gtest.h"

namespace oss_fuzz {
namespace indexer {
namespace {

using ::testing::ElementsAreArray;

class SqliteTest : public ::testing::Test {
 protected:
  static void SetUpTestSuite() { ASSERT_TRUE(InitializeSqlite()); }
};

TEST_F(SqliteTest, SaveAndLoad) {
  FlatIndex index;
  index.locations = {
      Location("a/b.cc", 1, 2),
      Location("c/d.h", 3, 4),
  };
  index.entities = {
      Entity(Entity::Kind::kEnumConstant, "", "kEnumValue", "", 1, false, false,
             std::nullopt, "123"),
      Entity(Entity::Kind::kClass, "foo::", "Bar", "", 0),
      Entity(Entity::Kind::kFunction, "foo::", "Bar", "()", 1, false, false,
             std::nullopt, std::nullopt,
             Entity::VirtualMethodKind::kPureVirtual),
  };
  index.references = {
      Reference(/*entity_id=*/0, /*location_id=*/1),
      Reference(/*entity_id=*/1, /*location_id=*/0),
  };
  index.virtual_method_links = {
      VirtualMethodLink(2, 2),
  };
  index.incremental_indexing_metadata.emplace();
  index.incremental_indexing_metadata->translation_units = {
      TranslationUnit("tu1"),
      TranslationUnit("tu2"),
  };
  index.incremental_indexing_metadata->entity_translation_units = {
      EntityTranslationUnit(/*entity_id=*/0, /*tu_id=*/0),
      EntityTranslationUnit(/*entity_id=*/1, /*tu_id=*/1),
      EntityTranslationUnit(/*entity_id=*/2, /*tu_id=*/1),
  };
  index.incremental_indexing_metadata->reference_translation_units = {
      ReferenceTranslationUnit(/*reference_id=*/0, /*tu_id=*/1),
      ReferenceTranslationUnit(/*reference_id=*/1, /*tu_id=*/0),
  };

  const std::string path =
      (std::filesystem::path(::testing::TempDir()) / "test.sqlite").string();

  ASSERT_TRUE(SaveAsSqlite(index, path));
  std::optional<FlatIndex> loaded_index = LoadFromSqlite(path);
  ASSERT_TRUE(loaded_index.has_value());

  EXPECT_THAT(loaded_index->locations, ElementsAreArray(index.locations));
  EXPECT_THAT(loaded_index->entities, ElementsAreArray(index.entities));
  EXPECT_THAT(loaded_index->references, ElementsAreArray(index.references));
  EXPECT_THAT(loaded_index->virtual_method_links,
              ElementsAreArray(index.virtual_method_links));
  ASSERT_TRUE(loaded_index->incremental_indexing_metadata.has_value());
  EXPECT_THAT(
      loaded_index->incremental_indexing_metadata->translation_units,
      ElementsAreArray(index.incremental_indexing_metadata->translation_units));
  EXPECT_THAT(
      loaded_index->incremental_indexing_metadata->entity_translation_units,
      ElementsAreArray(
          index.incremental_indexing_metadata->entity_translation_units));
  EXPECT_THAT(
      loaded_index->incremental_indexing_metadata->reference_translation_units,
      ElementsAreArray(
          index.incremental_indexing_metadata->reference_translation_units));
}

}  // namespace
}  // namespace indexer
}  // namespace oss_fuzz
