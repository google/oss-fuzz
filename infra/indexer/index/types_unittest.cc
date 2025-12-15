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

#include <cstddef>
#include <vector>

#include "gtest/gtest.h"
#include "absl/hash/hash_testing.h"

namespace oss_fuzz {
namespace indexer {
namespace {
std::vector<Location> GetTestLocations() {
  // This should return a sorted vector of Locations.
  return {
      Location("/some/file/path.cc", 0, 1),
      Location("/some/file/path.cc", 0, 99),
      Location("/some/other/file/path.cc", 0, 1),
      Location("/some/other/file/path.cc", 0, 99),
  };
}

std::vector<Entity> GetTestEntities() {
  // This should return a sorted vector of Entities.
  return {
      Entity(Entity::Kind::kVariable, "bar::", "foo", "", 0),
      Entity(Entity::Kind::kEnum, "foo::", "bar", "", 0),
      Entity(Entity::Kind::kVariable, "foo::", "bar", "", 0),
      Entity(Entity::Kind::kVariable, "foo::", "bar", "", 1),
      Entity(Entity::Kind::kVariable, "foo::", "bar", "", 1,
             /*is_incomplete=*/true),
      Entity(Entity::Kind::kFunction, "foo::", "bar", "()", 0),
      Entity(Entity::Kind::kFunction, "foo::", "bar", "(int baz)", 0),
      Entity(Entity::Kind::kEnum, "foo::", "foo", "", 0),
  };
}

std::vector<Reference> GetTestReferences() {
  // This should return a sorted vector of References.
  return {
      Reference(0, 0),
      Reference(0, 1),
      Reference(1, 1),
  };
}
}  // namespace

TEST(LocationTest, TestEquality) {
  auto locations = GetTestLocations();
  for (size_t i = 0; i < locations.size(); ++i) {
    for (size_t j = 0; j < locations.size(); ++j) {
      if (i == j) {
        ASSERT_EQ(locations[i], locations[j]) << i << " == " << j;
      } else {
        ASSERT_NE(locations[i], locations[j]) << i << " == " << j;
      }
    }
  }
}

TEST(LocationTest, TestStrictComparison) {
  auto locations = GetTestLocations();
  for (size_t i = 0; i < locations.size(); ++i) {
    for (size_t j = 0; j < locations.size(); ++j) {
      if (i < j) {
        ASSERT_TRUE(locations[i] < locations[j]) << i << " < " << j;
        ASSERT_FALSE(locations[i] > locations[j]) << i << " > " << j;
      } else if (i > j) {
        ASSERT_FALSE(locations[i] < locations[j]) << i << " < " << j;
        ASSERT_TRUE(locations[i] > locations[j]) << i << " > " << j;
      } else {
        ASSERT_FALSE(locations[i] < locations[j]) << i << " < " << j;
        ASSERT_FALSE(locations[i] > locations[j]) << i << " > " << j;
      }
    }
  }
}

TEST(LocationTest, TestComparison) {
  auto locations = GetTestLocations();
  for (size_t i = 0; i < locations.size(); ++i) {
    for (size_t j = 0; j < locations.size(); ++j) {
      if (i < j) {
        ASSERT_TRUE(locations[i] <= locations[j]) << i << " <= " << j;
        ASSERT_FALSE(locations[i] >= locations[j]) << i << " >= " << j;
      } else if (i > j) {
        ASSERT_FALSE(locations[i] <= locations[j]) << i << " <= " << j;
        ASSERT_TRUE(locations[i] >= locations[j]) << i << " >= " << j;
      } else {
        ASSERT_TRUE(locations[i] <= locations[j]) << i << " <= " << j;
        ASSERT_TRUE(locations[i] >= locations[j]) << i << " >= " << j;
      }
    }
  }
}

TEST(LocationTest, TestHash) {
  EXPECT_TRUE(absl::VerifyTypeImplementsAbslHashCorrectly(GetTestLocations()));
}

TEST(EntityTest, TestEquality) {
  auto entities = GetTestEntities();
  for (size_t i = 0; i < entities.size(); ++i) {
    for (size_t j = 0; j < entities.size(); ++j) {
      if (i == j) {
        ASSERT_EQ(entities[i], entities[j]) << i << " == " << j;
      } else {
        ASSERT_NE(entities[i], entities[j]) << i << " == " << j;
      }
    }
  }
}

TEST(EntityTest, TestStrictComparison) {
  auto entities = GetTestEntities();
  for (size_t i = 0; i < entities.size(); ++i) {
    for (size_t j = 0; j < entities.size(); ++j) {
      if (i < j) {
        ASSERT_TRUE(entities[i] < entities[j]) << i << " < " << j;
        ASSERT_FALSE(entities[i] > entities[j]) << i << " > " << j;
      } else if (i > j) {
        ASSERT_FALSE(entities[i] < entities[j]) << i << " < " << j;
        ASSERT_TRUE(entities[i] > entities[j]) << i << " > " << j;
      } else {
        ASSERT_FALSE(entities[i] < entities[j]) << i << " < " << j;
        ASSERT_FALSE(entities[i] > entities[j]) << i << " > " << j;
      }
    }
  }
}

TEST(EntityTest, TestComparison) {
  auto entities = GetTestEntities();
  for (size_t i = 0; i < entities.size(); ++i) {
    for (size_t j = 0; j < entities.size(); ++j) {
      if (i < j) {
        ASSERT_TRUE(entities[i] <= entities[j]) << i << " <= " << j;
        ASSERT_FALSE(entities[i] >= entities[j]) << i << " >= " << j;
      } else if (i > j) {
        ASSERT_FALSE(entities[i] <= entities[j]) << i << " <= " << j;
        ASSERT_TRUE(entities[i] >= entities[j]) << i << " >= " << j;
      } else {
        ASSERT_TRUE(entities[i] <= entities[j]) << i << " <= " << j;
        ASSERT_TRUE(entities[i] >= entities[j]) << i << " >= " << j;
      }
    }
  }
}

TEST(EntityTest, TestHash) {
  EXPECT_TRUE(absl::VerifyTypeImplementsAbslHashCorrectly(GetTestEntities()));
}

TEST(ReferenceTest, TestEquality) {
  auto references = GetTestReferences();
  for (size_t i = 0; i < references.size(); ++i) {
    for (size_t j = 0; j < references.size(); ++j) {
      if (i == j) {
        ASSERT_EQ(references[i], references[j]) << i << " == " << j;
      } else {
        ASSERT_NE(references[i], references[j]) << i << " == " << j;
      }
    }
  }
}

TEST(ReferenceTest, TestStrictComparison) {
  auto references = GetTestReferences();
  for (size_t i = 0; i < references.size(); ++i) {
    for (size_t j = 0; j < references.size(); ++j) {
      if (i < j) {
        ASSERT_TRUE(references[i] < references[j]) << i << " < " << j;
        ASSERT_FALSE(references[i] > references[j]) << i << " > " << j;
      } else if (i > j) {
        ASSERT_FALSE(references[i] < references[j]) << i << " < " << j;
        ASSERT_TRUE(references[i] > references[j]) << i << " > " << j;
      } else {
        ASSERT_FALSE(references[i] < references[j]) << i << " < " << j;
        ASSERT_FALSE(references[i] > references[j]) << i << " > " << j;
      }
    }
  }
}

TEST(ReferenceTest, TestComparison) {
  auto references = GetTestReferences();
  for (size_t i = 0; i < references.size(); ++i) {
    for (size_t j = 0; j < references.size(); ++j) {
      if (i < j) {
        ASSERT_TRUE(references[i] <= references[j]) << i << " <= " << j;
        ASSERT_FALSE(references[i] >= references[j]) << i << " >= " << j;
      } else if (i > j) {
        ASSERT_FALSE(references[i] <= references[j]) << i << " <= " << j;
        ASSERT_TRUE(references[i] >= references[j]) << i << " >= " << j;
      } else {
        ASSERT_TRUE(references[i] <= references[j]) << i << " <= " << j;
        ASSERT_TRUE(references[i] >= references[j]) << i << " >= " << j;
      }
    }
  }
}

TEST(ReferenceTest, TestHash) {
  EXPECT_TRUE(absl::VerifyTypeImplementsAbslHashCorrectly(GetTestReferences()));
}

}  // namespace indexer
}  // namespace oss_fuzz
