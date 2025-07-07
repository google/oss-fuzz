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

#include "indexer/frontend/frontend.h"

#include <filesystem>  // NOLINT
#include <fstream>
#include <iostream>
#include <memory>
#include <optional>
#include <sstream>
#include <string>
#include <utility>
#include <vector>

#include "indexer/frontend/index_action.h"
#include "indexer/index/file_copier.h"
#include "indexer/index/in_memory_index.h"
#include "indexer/index/types.h"
#include "indexer/merge_queue.h"
#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/flags/declare.h"
#include "absl/flags/flag.h"
#include "absl/log/check.h"
#include "clang/Tooling/Tooling.h"

ABSL_DECLARE_FLAG(std::vector<std::string>, ignore_pragmas);

namespace oss_fuzz {
namespace indexer {
namespace frontend_internal {
using ::testing::ElementsAre;

TEST(ParseCommandLineTest, BasicWhitespaceSeparation) {
  std::vector<std::string> args = ParseCommandLine("one two   three\tfour");
  EXPECT_THAT(args, ElementsAre("one", "two", "three", "four"));
}

TEST(ParseCommandLineTest, SingleQuotedWords) {
  std::vector<std::string> args = ParseCommandLine("hello 'world' 'again '");
  EXPECT_THAT(args, ElementsAre("hello", "world", "again "));
}

TEST(ParseCommandLineTest, DoubleQuotedWords) {
  std::vector<std::string> args =
      ParseCommandLine("test \"more words\" \"inside \" ");
  EXPECT_THAT(args, ElementsAre("test", "more words", "inside "));
}

TEST(ParseCommandLineTest, BackslashInsideSingleQuotes) {
  std::vector<std::string> args = ParseCommandLine("prefix 'a\\b' 'c\\d'");
  EXPECT_THAT(args, ElementsAre("prefix", "a\\b", "c\\d"));
}

TEST(ParseCommandLineTest, BackslashInsideDoubleQuotes) {
  std::vector<std::string> args =
      ParseCommandLine("item1 \"item2 \\' \\\"item3 \"");
  EXPECT_THAT(args, ElementsAre("item1", "item2 ' \"item3 "));
}

TEST(ParseCommandLineTest, EscapedDoubleQuoteInsideDoubleQuotes) {
  std::vector<std::string> args =
      ParseCommandLine("value1 \"value2\\\" \\\"value3 \"");
  EXPECT_THAT(args, ElementsAre("value1", "value2\" \"value3 "));
}

TEST(ParseCommandLineTest, UnterminatedDoubleQuote) {
  std::vector<std::string> args = ParseCommandLine("start \"middle end '");
  EXPECT_THAT(args, ElementsAre("start", "middle end '"));
}

TEST(ParseCommandLineTest, EmptyQuotedStrings) {
  std::vector<std::string> args = ParseCommandLine("before '' \"\" after");
  EXPECT_THAT(args, ElementsAre("before", "", "", "after"));
}

TEST(ParseCommandLineTest, HashInsideSingleQuotes) {
  std::vector<std::string> args = ParseCommandLine("'#'");
  EXPECT_THAT(args, ElementsAre("#"));
}

TEST(ParseCommandLineTest, HashInsideDoubleQuotes) {
  std::vector<std::string> args = ParseCommandLine("another \"#\" here");
  EXPECT_THAT(args, ElementsAre("another", "#", "here"));
}

}  // namespace frontend_internal

namespace {
std::unique_ptr<InMemoryIndex> IndexSnippet(
    std::string code, const std::vector<std::string>& extra_args = {},
    bool fail_on_error = false) {
  auto source_dir = std::filesystem::path(::testing::TempDir()) / "src";
  std::filesystem::remove_all(source_dir);
  CHECK(std::filesystem::create_directory(source_dir));
  {
    std::ofstream source_file(source_dir / "snippet.cc");
    source_file << code;
    CHECK(source_file.good());
  }
  std::string source_file_path = (source_dir / "snippet.cc").string();
  std::string source_dir_path = source_dir.string();

  auto index_dir = std::filesystem::path(::testing::TempDir()) / "idx";
  std::filesystem::remove_all(index_dir);
  CHECK(std::filesystem::create_directory(index_dir));
  std::string index_dir_path = index_dir.string();
  std::string sysroot_path = "/";

  FileCopier file_copier(source_dir_path, index_dir_path, {sysroot_path});

  std::unique_ptr<MergeQueue> merge_queue = MergeQueue::Create(1);
  auto index_action = std::make_unique<IndexAction>(file_copier, *merge_queue);
  const bool result = clang::tooling::runToolOnCodeWithArgs(
      std::move(index_action), code, extra_args, source_file_path);
  merge_queue->WaitUntilComplete();
  auto index = merge_queue->TakeIndex();

  if (fail_on_error && !result) {
    return nullptr;
  }

  return index;
}

std::string KindToString(Entity::Kind kind) {
  if (kind == Entity::Kind::kMacro) {
    return "Macro";
  } else if (kind == Entity::Kind::kEnum) {
    return "Enum";
  } else if (kind == Entity::Kind::kEnumConstant) {
    return "EnumConstant";
  } else if (kind == Entity::Kind::kVariable) {
    return "Variable";
  } else if (kind == Entity::Kind::kFunction) {
    return "Function";
  } else if (kind == Entity::Kind::kClass) {
    return "Class";
  } else if (kind == Entity::Kind::kType) {
    return "Type";
  } else {
    return "Invalid";
  }
}

void PrintRequiredEntityParameters(const FlatIndex& index,
                                   const Entity& entity) {
  const auto& location = index.locations[entity.location_id()];
  std::cerr << "Entity::Kind::k" << KindToString(entity.kind()) << ", " << "\""
            << entity.name_prefix() << "\", " << "\"" << entity.name() << "\", "
            << "\"" << entity.name_suffix() << "\", " << "\"" << location.path()
            << "\", " << location.start_line() << ", " << location.end_line();
}

void PrintAllEntityParameters(const FlatIndex& index, const Entity& entity);

void PrintOptionalEntityParameters(const FlatIndex& index,
                                   const Entity& entity) {
  std::vector<const char*> preceding_defaults;
  auto flush_preceding_defaults = [&preceding_defaults]() {
    for (const auto& preceding_default : preceding_defaults) {
      std::cerr << preceding_default;
    }
    preceding_defaults.clear();
  };

  if (entity.is_incomplete()) {
    std::cerr << ", /*is_incomplete=*/true";
  } else {
    preceding_defaults.push_back(", /*is_incomplete=*/false");
  }
  if (entity.canonical_entity_id().has_value()) {
    flush_preceding_defaults();
    std::cerr << ", /*canonical_entity_id=*/RequiredEntityId(index, ";
    const Entity& canonical_entity =
        index.entities[*entity.canonical_entity_id()];
    PrintAllEntityParameters(index, canonical_entity);
    std::cerr << ")";
  } else {
    preceding_defaults.push_back(", /*canonical_entity_id=*/std::nullopt");
  }
  if (entity.implicitly_defined_for_entity_id().has_value()) {
    for (const auto& preceding_default : preceding_defaults) {
      std::cerr << preceding_default;
    }
    preceding_defaults.clear();

    std::cerr
        << ", /*implicitly_defined_for_entity_id=*/RequiredEntityId(index, ";
    const Entity& implicitly_defined_for_entity =
        index.entities[*entity.implicitly_defined_for_entity_id()];
    PrintAllEntityParameters(index, implicitly_defined_for_entity);
    std::cerr << ")";
  } else {
    preceding_defaults.push_back(
        ", /*implicitly_defined_for_entity_id=*/std::nullopt");
  }
  if (entity.enum_value().has_value()) {
    flush_preceding_defaults();
    std::cerr << ", /*enum_value=*/\"" << *entity.enum_value() << "\"";
  }
}

void PrintAllEntityParameters(const FlatIndex& index, const Entity& entity) {
  PrintRequiredEntityParameters(index, entity);
  PrintOptionalEntityParameters(index, entity);
}

// Helper function for adding new tests, this will print all the potentially
// valid `EXPECT...`s for a given index. These should be vetted and cleaned up
// before adding to the test body. This should not be referenced in committed
// tests.
[[maybe_unused]] void PrintValidExpectations(const FlatIndex& index) {
  for (EntityId entity_id = 0; entity_id < index.entities.size(); ++entity_id) {
    const auto& entity = index.entities[entity_id];
    const auto& location = index.locations[entity.location_id()];
    if (location.path() == "<built-in>" ||
        location.path() == "<command line>") {
      continue;
    }

    std::cerr << "EXPECT_HAS_ENTITY(index, ";
    PrintAllEntityParameters(index, entity);
    std::cerr << ");\n";

    for (const auto& reference : index.references) {
      if (reference.entity_id() == entity_id) {
        const auto& ref_location = index.locations[reference.location_id()];
        std::cerr << "EXPECT_HAS_REFERENCE(index, ";
        PrintRequiredEntityParameters(index, entity);
        std::cerr << ", \"" << ref_location.path() << "\", "
                  << ref_location.start_line() << ", "
                  << ref_location.end_line();
        PrintOptionalEntityParameters(index, entity);
        std::cerr << ");\n";
      }
    }
  }
}

std::string DebugPrintIndex(const FlatIndex& index) {
  std::stringstream stream;
  for (EntityId entity_id = 0; entity_id < index.entities.size(); ++entity_id) {
    const auto& entity = index.entities[entity_id];
    const auto& location = index.locations[entity.location_id()];
    if (location.path().empty() || location.path() == "<built-in>" ||
        location.path() == "<command line>") {
      continue;
    }

    auto print_entity = [&stream, &index](const Entity& entity,
                                          const char* indent = "") {
      const auto& location = index.locations[entity.location_id()];
      stream << indent << KindToString(entity.kind()) << " `"
             << entity.name_prefix() << entity.name() << entity.name_suffix()
             << "`\n"
             << indent
             << (entity.is_incomplete() ? " Declared at \"" : "  Defined at \"")
             << location.path() << "\" lines " << location.start_line() << "-"
             << location.end_line() << "\n";
    };

    print_entity(entity);
    if (entity.canonical_entity_id().has_value()) {
      const auto& canonical_entity =
          index.entities[*entity.canonical_entity_id()];
      stream << "  Canonical:\n";
      print_entity(canonical_entity, /*indent=*/"    ");
    }
    if (entity.implicitly_defined_for_entity_id().has_value()) {
      const auto& implicitly_defined_for_entity =
          index.entities[*entity.implicitly_defined_for_entity_id()];
      stream << "  Implicitly defined for:\n";
      print_entity(implicitly_defined_for_entity, /*indent=*/"    ");
    }
    if (entity.enum_value().has_value()) {
      stream << "  Enum value: " << *entity.enum_value() << "\n";
    }
    for (const auto& reference : index.references) {
      if (reference.entity_id() == entity_id) {
        const auto& ref_location = index.locations[reference.location_id()];
        stream << "  Referenced at \"" << ref_location.path() << "\" lines "
               << ref_location.start_line() << "-" << ref_location.end_line()
               << "\n";
      }
    }
  }
  return stream.str();
}

std::optional<Entity> FindEntity(
    const FlatIndex& index, Entity::Kind kind, std::string name_prefix,
    std::string name, std::string name_suffix, std::string path, int start_line,
    int end_line, bool is_incomplete = false,
    const std::optional<EntityId>& canonical_entity_id = std::nullopt,
    const std::optional<EntityId>& implicitly_defined_for_entity_id =
        std::nullopt,
    const std::optional<std::string> enum_value = std::nullopt) {
  std::optional<Entity> entity;
  for (LocationId location_id = 0; location_id < index.locations.size();
       ++location_id) {
    const auto& index_location = index.locations[location_id];
    if (index_location.path() == path &&
        index_location.start_line() == start_line &&
        index_location.end_line() == end_line) {
      entity = {kind,
                name_prefix,
                name,
                name_suffix,
                location_id,
                is_incomplete,
                /*is_weak=*/false,
                canonical_entity_id,
                implicitly_defined_for_entity_id,
                enum_value};
      break;
    }
  }

  if (!entity.has_value()) {
    return std::nullopt;
  }

  for (const auto& index_entity : index.entities) {
    if (*entity == index_entity) {
      return entity;
    }
  }

  return std::nullopt;
}

bool IndexHasEntity(
    const FlatIndex& index, Entity::Kind kind, std::string name_prefix,
    std::string name, std::string name_suffix, std::string path, int start_line,
    int end_line, bool is_incomplete = false,
    const std::optional<EntityId>& canonical_entity_id = std::nullopt,
    const std::optional<EntityId>& implicitly_defined_for_entity_id =
        std::nullopt,
    const std::optional<std::string> enum_value = std::nullopt) {
  return FindEntity(index, kind, name_prefix, name, name_suffix, path,
                    start_line, end_line, is_incomplete, canonical_entity_id,
                    implicitly_defined_for_entity_id, enum_value)
      .has_value();
}

bool IndexHasReference(
    const FlatIndex& index, Entity::Kind kind, std::string name_prefix,
    std::string name, std::string name_suffix, std::string path, int start_line,
    int end_line, std::string ref_path, int ref_start_line, int ref_end_line,
    bool is_incomplete = false,
    std::optional<EntityId> canonical_entity_id = std::nullopt,
    std::optional<EntityId> implicitly_defined_for_entity_id = std::nullopt,
    std::optional<std::string> enum_value = std::nullopt) {
  LocationId ref_location_id = kInvalidLocationId;
  EntityId ref_entity_id = kInvalidEntityId;

  std::optional<Entity> entity;
  for (LocationId location_id = 0; location_id < index.locations.size();
       ++location_id) {
    const auto& index_location = index.locations[location_id];
    if (index_location.path() == path &&
        index_location.start_line() == start_line &&
        index_location.end_line() == end_line) {
      entity = {kind,
                name_prefix,
                name,
                name_suffix,
                location_id,
                is_incomplete,
                /*is_weak=*/false,
                canonical_entity_id,
                implicitly_defined_for_entity_id,
                enum_value};
    }

    if (index_location.path() == ref_path &&
        index_location.start_line() == ref_start_line &&
        index_location.end_line() == ref_end_line) {
      ref_location_id = location_id;
    }
  }

  if (!entity.has_value()) {
    return false;
  }

  for (EntityId entity_id = 0; entity_id < index.entities.size(); ++entity_id) {
    const auto& index_entity = index.entities[entity_id];
    if (*entity == index_entity) {
      ref_entity_id = entity_id;
    }
  }

  if (ref_entity_id == kInvalidEntityId ||
      ref_location_id == kInvalidLocationId) {
    return false;
  }

  for (const auto& reference : index.references) {
    if (reference.entity_id() == ref_entity_id &&
        reference.location_id() == ref_location_id) {
      return true;
    }
  }

  return false;
}

template <typename... Args>
std::optional<EntityId> RequiredEntityId(const FlatIndex& index,
                                         Args&&... args) {
  auto entity = FindEntity(index, std::forward<Args>(args)...);
  EXPECT_TRUE(entity.has_value());
  if (!entity.has_value()) {
    return std::nullopt;
  }

  for (EntityId entity_id = 0; entity_id < index.entities.size(); ++entity_id) {
    const Entity& other_entity = index.entities[entity_id];
    if (entity == other_entity) {
      return entity_id;
    }
  }
  return std::nullopt;
}
}  // anonymous namespace

#define EXPECT_HAS_ENTITY(index, ...) \
  EXPECT_TRUE(IndexHasEntity(index, __VA_ARGS__)) << DebugPrintIndex(index)

#define EXPECT_HAS_REFERENCE(index, ...) \
  EXPECT_TRUE(IndexHasReference(index, __VA_ARGS__)) << DebugPrintIndex(index)

TEST(FrontendTest, MacroDefinition) {
  auto index = IndexSnippet("#define MACRO 1\n")->Export();
  EXPECT_HAS_ENTITY(index, Entity::Kind::kMacro, "", "MACRO", "", "snippet.cc",
                    1, 1);
}

TEST(FrontendTest, MultilineMacroDefinition) {
  auto index = IndexSnippet(
                   "#define MACRO 1\\\n"
                   "  + 2 + 3\\\n"
                   "  + 4 + 5\n")
                   ->Export();
  EXPECT_HAS_ENTITY(index, Entity::Kind::kMacro, "", "MACRO", "", "snippet.cc",
                    1, 3);
}

TEST(FrontendTest, MacroArgsDefinition) {
  auto index = IndexSnippet("#define MACRO(x) (void)(x)\n")->Export();
  EXPECT_HAS_ENTITY(index, Entity::Kind::kMacro, "", "MACRO", "", "snippet.cc",
                    1, 1);
}

TEST(FrontendTest, MacroVarargsDefinition) {
  auto index =
      IndexSnippet("#define MACRO(...) (void)(__VA_ARGS__)\n")->Export();
  EXPECT_HAS_ENTITY(index, Entity::Kind::kMacro, "", "MACRO", "", "snippet.cc",
                    1, 1);
}

TEST(FrontendTest, MacroExpansion) {
  auto index = IndexSnippet(
                   "#define MACRO 1\n"
                   "constexpr int a = MACRO;\n")
                   ->Export();
  EXPECT_HAS_REFERENCE(index, Entity::Kind::kMacro, "", "MACRO", "",
                       "snippet.cc", 1, 1, "snippet.cc", 2, 2);
}

TEST(FrontendTest, MacroArgsExpansion) {
  auto index = IndexSnippet(
                   "#define MACRO(x) (x)\n"
                   "constexpr int a = MACRO(1);\n")
                   ->Export();
  EXPECT_HAS_REFERENCE(index, Entity::Kind::kMacro, "", "MACRO", "",
                       "snippet.cc", 1, 1, "snippet.cc", 2, 2);
}

TEST(FrontendTest, MacroVarargsExpansion) {
  auto index = IndexSnippet(
                   "#define MACRO(...) __VA_ARGS__\n"
                   "int MACRO(a, b, c);\n")
                   ->Export();
  EXPECT_HAS_REFERENCE(index, Entity::Kind::kMacro, "", "MACRO", "",
                       "snippet.cc", 1, 1, "snippet.cc", 2, 2);
}

TEST(FrontendTest, NestedMacroExpansion) {
  auto index = IndexSnippet(
                   "#define INNER_MACRO a\n"
                   "#define OUTER_MACRO INNER_MACRO = 1\n"
                   "constexpr int OUTER_MACRO;\n")
                   ->Export();
  EXPECT_HAS_REFERENCE(index, Entity::Kind::kMacro, "", "OUTER_MACRO", "",
                       "snippet.cc", 2, 2, "snippet.cc", 3, 3);
  EXPECT_HAS_REFERENCE(index, Entity::Kind::kMacro, "", "INNER_MACRO", "",
                       "snippet.cc", 1, 1, "snippet.cc", 3, 3);
}

TEST(FrontendTest, MultipleMacroExpansion) {
  auto index = IndexSnippet(
                   "#define INNER_MACRO(x) x\n"
                   "#define OUTER_MACRO(x, y) INNER_MACRO(x) = y\n"
                   "constexpr int OUTER_MACRO(a, 1);\n"
                   "constexpr int OUTER_MACRO(b, 2);\n"
                   "constexpr int OUTER_MACRO(c, 3);\n")
                   ->Export();
  EXPECT_HAS_REFERENCE(index, Entity::Kind::kMacro, "", "OUTER_MACRO", "",
                       "snippet.cc", 2, 2, "snippet.cc", 3, 3);
  EXPECT_HAS_REFERENCE(index, Entity::Kind::kMacro, "", "OUTER_MACRO", "",
                       "snippet.cc", 2, 2, "snippet.cc", 4, 4);
  EXPECT_HAS_REFERENCE(index, Entity::Kind::kMacro, "", "OUTER_MACRO", "",
                       "snippet.cc", 2, 2, "snippet.cc", 5, 5);
  EXPECT_HAS_REFERENCE(index, Entity::Kind::kMacro, "", "INNER_MACRO", "",
                       "snippet.cc", 1, 1, "snippet.cc", 3, 3);
  EXPECT_HAS_REFERENCE(index, Entity::Kind::kMacro, "", "INNER_MACRO", "",
                       "snippet.cc", 1, 1, "snippet.cc", 4, 4);
  EXPECT_HAS_REFERENCE(index, Entity::Kind::kMacro, "", "INNER_MACRO", "",
                       "snippet.cc", 1, 1, "snippet.cc", 5, 5);
}

TEST(FrontendTest, EnumDeclaration) {
  auto index = IndexSnippet(
                   "enum Enum {\n"
                   "  kEnumConstant0 = 0,\n"
                   "  kEnumConstant1 = 1,\n"
                   "  kElaborateEnumConstant = "
                   "kEnumConstant0 * kEnumConstant1 - 7,\n"
                   "};\n"
                   "Enum enum_instance = kEnumConstant0;\n"
                   "enum class LargeUnsigned : decltype(0ULL) {\n"
                   "  kNonNegative = 0xffffffffffffffff,\n"
                   "};\n"
                   "enum class Huge : unsigned __int128 {\n"
                   "  kValue = ~(unsigned __int128)(0),\n"
                   "};\n")
                   ->Export();
  EXPECT_HAS_ENTITY(index, Entity::Kind::kEnum, "", "Enum", "", "snippet.cc", 1,
                    5);
  EXPECT_HAS_ENTITY(index, Entity::Kind::kEnumConstant, "", "kEnumConstant0",
                    "", "snippet.cc", 2, 2, /*is_incomplete=*/false,
                    /*canonical_entity_id=*/std::nullopt,
                    /*implicitly_defined_for_entity_id=*/std::nullopt,
                    /*enum_value=*/"0");
  EXPECT_HAS_ENTITY(index, Entity::Kind::kEnumConstant, "", "kEnumConstant1",
                    "", "snippet.cc", 3, 3, /*is_incomplete=*/false,
                    /*canonical_entity_id=*/std::nullopt,
                    /*implicitly_defined_for_entity_id=*/std::nullopt,
                    /*enum_value=*/"1");
  EXPECT_HAS_ENTITY(index, Entity::Kind::kEnumConstant, "",
                    "kElaborateEnumConstant", "", "snippet.cc", 4, 4,
                    /*is_incomplete=*/false,
                    /*canonical_entity_id=*/std::nullopt,
                    /*implicitly_defined_for_entity_id=*/std::nullopt,
                    /*enum_value=*/"-7");
  EXPECT_HAS_ENTITY(index, Entity::Kind::kVariable, "", "enum_instance", "",
                    "snippet.cc", 6, 6);
  EXPECT_HAS_REFERENCE(index, Entity::Kind::kEnum, "", "Enum", "", "snippet.cc",
                       1, 5, "snippet.cc", 6, 6);
  EXPECT_HAS_REFERENCE(index, Entity::Kind::kEnumConstant, "", "kEnumConstant0",
                       "", "snippet.cc", 2, 2, "snippet.cc", 6, 6,
                       /*is_incomplete=*/false,
                       /*canonical_entity_id=*/std::nullopt,
                       /*implicitly_defined_for_entity_id=*/std::nullopt,
                       /*enum_value=*/"0");
  EXPECT_HAS_ENTITY(index, Entity::Kind::kEnumConstant, "Huge::", "kValue", "",
                    "snippet.cc", 11, 11, /*is_incomplete=*/false,
                    /*canonical_entity_id=*/std::nullopt,
                    /*implicitly_defined_for_entity_id=*/std::nullopt,
                    /*enum_value=*/"340282366920938463463374607431768211455");
  EXPECT_HAS_ENTITY(index, Entity::Kind::kEnumConstant,
                    "LargeUnsigned::", "kNonNegative", "", "snippet.cc", 8, 8,
                    /*is_incomplete=*/false,
                    /*canonical_entity_id=*/std::nullopt,
                    /*implicitly_defined_for_entity_id=*/std::nullopt,
                    /*enum_value=*/"18446744073709551615");
}

TEST(FrontendTest, EnumClassDeclaration) {
  auto index = IndexSnippet(
                   "enum class Enum : char {\n"
                   "  kEnumConstant0 = 0,\n"
                   "  kEnumConstant1 = 1,\n"
                   "};\n"
                   "Enum enum_instance = Enum::kEnumConstant0;\n")
                   ->Export();
  EXPECT_HAS_ENTITY(index, Entity::Kind::kEnum, "", "Enum", "", "snippet.cc", 1,
                    4);
  EXPECT_HAS_ENTITY(index, Entity::Kind::kEnumConstant,
                    "Enum::", "kEnumConstant0", "", "snippet.cc", 2, 2,
                    /*is_incomplete=*/false,
                    /*canonical_entity_id=*/std::nullopt,
                    /*implicitly_defined_for_entity_id=*/std::nullopt,
                    /*enum_value=*/"0");
  EXPECT_HAS_ENTITY(index, Entity::Kind::kEnumConstant,
                    "Enum::", "kEnumConstant1", "", "snippet.cc", 3, 3,
                    /*is_incomplete=*/false,
                    /*canonical_entity_id=*/std::nullopt,
                    /*implicitly_defined_for_entity_id=*/std::nullopt,
                    /*enum_value=*/"1");
  EXPECT_HAS_ENTITY(index, Entity::Kind::kVariable, "", "enum_instance", "",
                    "snippet.cc", 5, 5);
  EXPECT_HAS_REFERENCE(index, Entity::Kind::kEnum, "", "Enum", "", "snippet.cc",
                       1, 4, "snippet.cc", 5, 5);
  EXPECT_HAS_REFERENCE(index, Entity::Kind::kEnumConstant,
                       "Enum::", "kEnumConstant0", "", "snippet.cc", 2, 2,
                       "snippet.cc", 5, 5, /*is_incomplete=*/false,
                       /*canonical_entity_id=*/std::nullopt,
                       /*implicitly_defined_for_entity_id=*/std::nullopt,
                       /*enum_value=*/"0");
}

TEST(FrontendTest, NamespacedEnumDeclaration) {
  auto index = IndexSnippet(
                   "namespace n {\n"
                   "enum Enum {\n"
                   "  kEnumConstant0 = 0,\n"
                   "  kEnumConstant1 = 1,\n"
                   "};\n"
                   "Enum enum_instance0 = kEnumConstant0;\n"
                   "}  // namespace n\n"
                   "n::Enum enum_instance1 = n::kEnumConstant1;\n")
                   ->Export();
  EXPECT_HAS_ENTITY(index, Entity::Kind::kEnum, "n::", "Enum", "", "snippet.cc",
                    2, 5);
  EXPECT_HAS_ENTITY(index, Entity::Kind::kEnumConstant, "n::", "kEnumConstant0",
                    "", "snippet.cc", 3, 3, /*is_incomplete=*/false,
                    /*canonical_entity_id=*/std::nullopt,
                    /*implicitly_defined_for_entity_id=*/std::nullopt,
                    /*enum_value=*/"0");
  EXPECT_HAS_ENTITY(index, Entity::Kind::kEnumConstant, "n::", "kEnumConstant1",
                    "", "snippet.cc", 4, 4, /*is_incomplete=*/false,
                    /*canonical_entity_id=*/std::nullopt,
                    /*implicitly_defined_for_entity_id=*/std::nullopt,
                    /*enum_value=*/"1");
  EXPECT_HAS_ENTITY(index, Entity::Kind::kVariable, "n::", "enum_instance0", "",
                    "snippet.cc", 6, 6);
  EXPECT_HAS_ENTITY(index, Entity::Kind::kVariable, "", "enum_instance1", "",
                    "snippet.cc", 8, 8);
  EXPECT_HAS_REFERENCE(index, Entity::Kind::kEnum, "n::", "Enum", "",
                       "snippet.cc", 2, 5, "snippet.cc", 6, 6);
  EXPECT_HAS_REFERENCE(index, Entity::Kind::kEnumConstant,
                       "n::", "kEnumConstant0", "", "snippet.cc", 3, 3,
                       "snippet.cc", 6, 6, /*is_incomplete=*/false,
                       /*canonical_entity_id=*/std::nullopt,
                       /*implicitly_defined_for_entity_id=*/std::nullopt,
                       /*enum_value=*/"0");
  EXPECT_HAS_REFERENCE(index, Entity::Kind::kEnum, "n::", "Enum", "",
                       "snippet.cc", 2, 5, "snippet.cc", 8, 8);
  EXPECT_HAS_REFERENCE(index, Entity::Kind::kEnumConstant,
                       "n::", "kEnumConstant1", "", "snippet.cc", 4, 4,
                       "snippet.cc", 8, 8, /*is_incomplete=*/false,
                       /*canonical_entity_id=*/std::nullopt,
                       /*implicitly_defined_for_entity_id=*/std::nullopt,
                       /*enum_value=*/"1");
}

TEST(FrontendTest, NamespacedEnumClassDeclaration) {
  auto index = IndexSnippet(
                   "namespace n {\n"
                   "enum class Enum : char {\n"
                   "  kEnumConstant0 = 0,\n"
                   "  kEnumConstant1 = 1,\n"
                   "};\n"
                   "Enum enum_instance0 = Enum::kEnumConstant0;\n"
                   "}  // namespace n\n"
                   "n::Enum enum_instance1 = n::Enum::kEnumConstant1;\n")
                   ->Export();
  EXPECT_HAS_ENTITY(index, Entity::Kind::kEnum, "n::", "Enum", "", "snippet.cc",
                    2, 5);
  EXPECT_HAS_ENTITY(index, Entity::Kind::kEnumConstant,
                    "n::Enum::", "kEnumConstant0", "", "snippet.cc", 3, 3,
                    /*is_incomplete=*/false,
                    /*canonical_entity_id=*/std::nullopt,
                    /*implicitly_defined_for_entity_id=*/std::nullopt,
                    /*enum_value=*/"0");
  EXPECT_HAS_ENTITY(index, Entity::Kind::kEnumConstant,
                    "n::Enum::", "kEnumConstant1", "", "snippet.cc", 4, 4,
                    /*is_incomplete=*/false,
                    /*canonical_entity_id=*/std::nullopt,
                    /*implicitly_defined_for_entity_id=*/std::nullopt,
                    /*enum_value=*/"1");
  EXPECT_HAS_ENTITY(index, Entity::Kind::kVariable, "n::", "enum_instance0", "",
                    "snippet.cc", 6, 6);
  EXPECT_HAS_ENTITY(index, Entity::Kind::kVariable, "", "enum_instance1", "",
                    "snippet.cc", 8, 8);
  EXPECT_HAS_REFERENCE(index, Entity::Kind::kEnum, "n::", "Enum", "",
                       "snippet.cc", 2, 5, "snippet.cc", 6, 6);
  EXPECT_HAS_REFERENCE(index, Entity::Kind::kEnumConstant,
                       "n::Enum::", "kEnumConstant0", "", "snippet.cc", 3, 3,
                       "snippet.cc", 6, 6, /*is_incomplete=*/false,
                       /*canonical_entity_id=*/std::nullopt,
                       /*implicitly_defined_for_entity_id=*/std::nullopt,
                       /*enum_value=*/"0");
  EXPECT_HAS_REFERENCE(index, Entity::Kind::kEnum, "n::", "Enum", "",
                       "snippet.cc", 2, 5, "snippet.cc", 8, 8);
  EXPECT_HAS_REFERENCE(index, Entity::Kind::kEnumConstant,
                       "n::Enum::", "kEnumConstant1", "", "snippet.cc", 4, 4,
                       "snippet.cc", 8, 8, /*is_incomplete=*/false,
                       /*canonical_entity_id=*/std::nullopt,
                       /*implicitly_defined_for_entity_id=*/std::nullopt,
                       /*enum_value=*/"1");
}

TEST(FrontendTest, VariableDeclaration) {
  auto index = IndexSnippet(
                   "int foo = 0;\n"
                   "extern \"C\" int bar = 1;\n"
                   "volatile int* const baz = nullptr;\n"
                   "const int* (*qux)() = nullptr;\n")
                   ->Export();
  EXPECT_HAS_ENTITY(index, Entity::Kind::kVariable, "", "foo", "", "snippet.cc",
                    1, 1);
  EXPECT_HAS_ENTITY(index, Entity::Kind::kVariable, "", "bar", "", "snippet.cc",
                    2, 2);
  EXPECT_HAS_ENTITY(index, Entity::Kind::kVariable, "", "baz", "", "snippet.cc",
                    3, 3);
  EXPECT_HAS_ENTITY(index, Entity::Kind::kVariable, "", "qux", "", "snippet.cc",
                    4, 4);
}

TEST(FrontendTest, ArrayDeclaration) {
  auto index = IndexSnippet(
                   "const char foo[] = {\n"
                   "  'A', 'A', 'A', 'A', 'A', 'A', 'A', 'A',\n"
                   "  'B', 'B', 'B', 'B', 'B', 'B', 'B', 'B',\n"
                   "};\n"
                   "const char* bar = \"AAAAAAAAA\"\n"
                   "                  \"BBBBBBBBB\"\n"
                   "                  \"CCCCCCCCC\";\n"
                   "const char* baz = \"AAAAAAAAA\"\\\n"
                   "                  \"BBBBBBBBB\"\\\n"
                   "                  \"CCCCCCCCC\";\n")
                   ->Export();
  EXPECT_HAS_ENTITY(index, Entity::Kind::kVariable, "", "foo", "", "snippet.cc",
                    1, 4);
  EXPECT_HAS_ENTITY(index, Entity::Kind::kVariable, "", "bar", "", "snippet.cc",
                    5, 7);
  EXPECT_HAS_ENTITY(index, Entity::Kind::kVariable, "", "baz", "", "snippet.cc",
                    8, 10);
}

TEST(FrontendTest, AnonymousStructDeclaration) {
  auto index = IndexSnippet(
                   "struct {\n"
                   "  int foo;\n"
                   "} bar;\n")
                   ->Export();
  EXPECT_HAS_ENTITY(index, Entity::Kind::kClass, "", "(anonymous struct)", "",
                    "snippet.cc", 1, 3);
  EXPECT_HAS_ENTITY(index, Entity::Kind::kVariable,
                    "(anonymous struct)::", "foo", "", "snippet.cc", 2, 2);
  EXPECT_HAS_ENTITY(index, Entity::Kind::kVariable, "", "bar", "", "snippet.cc",
                    1, 3);
}

TEST(FrontendTest, ConstructorReference) {
  auto index = IndexSnippet(
                   "class TestClass {\n"
                   " public:\n"
                   "  TestClass() {}\n"
                   "};\n"
                   "template<typename T>\n"
                   "class Template {\n"
                   " public:\n"
                   "  Template() {}\n"
                   "};\n"
                   "class Derived : public Template<int> {};\n"
                   "int main() {\n"
                   "  TestClass instance;\n"
                   "  struct Test {} test;\n"
                   "  Derived();\n"
                   "}\n")
                   ->Export();
  EXPECT_HAS_REFERENCE(index, Entity::Kind::kFunction,
                       "TestClass::", "TestClass", "()", "snippet.cc", 3, 3,
                       "snippet.cc", 12, 12, /*is_incomplete=*/false);
  EXPECT_HAS_REFERENCE(index, Entity::Kind::kClass, "", "Derived", "",
                       "snippet.cc", 10, 10, "snippet.cc", 14, 14,
                       /*is_incomplete=*/false);
  EXPECT_HAS_REFERENCE(index, Entity::Kind::kFunction, "Derived::", "Derived",
                       "()", "snippet.cc", 10, 10, "snippet.cc", 14, 14,
                       /*is_incomplete=*/false,
                       /*canonical_entity_id=*/std::nullopt,
                       /*implicitly_defined_for_entity_id=*/
                       RequiredEntityId(index, Entity::Kind::kClass, "",
                                        "Derived", "", "snippet.cc", 10, 10));
  EXPECT_HAS_REFERENCE(
      index, Entity::Kind::kFunction, "main()::Test::", "Test", "()",
      "snippet.cc", 13, 13, "snippet.cc", 13, 13, /*is_incomplete=*/false,
      /*canonical_entity_id=*/std::nullopt,
      /*implicitly_defined_for_entity_id=*/
      RequiredEntityId(index, Entity::Kind::kClass, "main()::", "Test", "",
                       "snippet.cc", 13, 13));
}

TEST(FrontendTest, NamespacedVariableDeclaration) {
  auto index = IndexSnippet(
                   "namespace n {\n"
                   "int foo = 0;\n"
                   "namespace {\n"
                   "int bar = 1;\n"
                   "}  // anonymous namespace\n"
                   "}  // namespace n\n"
                   "int baz = 2;\n")
                   ->Export();
  EXPECT_HAS_ENTITY(index, Entity::Kind::kVariable, "n::", "foo", "",
                    "snippet.cc", 2, 2);
  EXPECT_HAS_ENTITY(index, Entity::Kind::kVariable,
                    "n::(anonymous namespace)::", "bar", "", "snippet.cc", 4,
                    4);
  EXPECT_HAS_ENTITY(index, Entity::Kind::kVariable, "", "baz", "", "snippet.cc",
                    7, 7);
}

TEST(FrontendTest, FunctionDeclaration) {
  auto index = IndexSnippet(
                   "int foo();\n"
                   "extern \"C\" int bar(int baz);\n")
                   ->Export();
  EXPECT_HAS_ENTITY(index, Entity::Kind::kFunction, "", "foo", "()",
                    "snippet.cc", 1, 1, /*is_incomplete=*/true);
  EXPECT_HAS_ENTITY(index, Entity::Kind::kFunction, "", "bar", "(int)",
                    "snippet.cc", 2, 2, /*is_incomplete=*/true);
  EXPECT_FALSE(IndexHasEntity(index, Entity::Kind::kVariable, "", "baz", "",
                              "snippet.cc", 2, 2));
}

TEST(FrontendTest, FunctionDefinition) {
  auto index = IndexSnippet(
                   "extern int foo(int bar);\n"
                   "int foo(int bar) {\n"
                   "  int baz = bar;\n"
                   "  return foo(baz) + bar;\n"
                   "}")
                   ->Export();
  EXPECT_FALSE(IndexHasEntity(index, Entity::Kind::kFunction, "", "foo",
                              "(int)", "snippet.cc", 1, 1));
  EXPECT_FALSE(IndexHasEntity(index, Entity::Kind::kVariable, "", "bar", "",
                              "snippet.cc", 1, 1));
  EXPECT_HAS_ENTITY(index, Entity::Kind::kFunction, "", "foo", "(int)",
                    "snippet.cc", 2, 5);
  EXPECT_HAS_ENTITY(index, Entity::Kind::kVariable, "", "bar", "", "snippet.cc",
                    2, 2);
  EXPECT_HAS_ENTITY(index, Entity::Kind::kVariable, "", "baz", "", "snippet.cc",
                    3, 3);
  EXPECT_HAS_REFERENCE(index, Entity::Kind::kVariable, "", "bar", "",
                       "snippet.cc", 2, 2, "snippet.cc", 3, 3);
  EXPECT_HAS_REFERENCE(index, Entity::Kind::kVariable, "", "bar", "",
                       "snippet.cc", 2, 2, "snippet.cc", 4, 4);
  EXPECT_HAS_REFERENCE(index, Entity::Kind::kVariable, "", "baz", "",
                       "snippet.cc", 3, 3, "snippet.cc", 4, 4);
  EXPECT_HAS_REFERENCE(index, Entity::Kind::kFunction, "", "foo", "(int)",
                       "snippet.cc", 2, 5, "snippet.cc", 4, 4);
}

TEST(FrontendTest, MacroWrappedFunctionDefinition1) {
  auto index = IndexSnippet(
                   "#define MACRO(x, y, z) x y z\n"
                   "MACRO(int, foo, (int bar)) {\n"
                   "  return bar;\n"
                   "}\n")
                   ->Export();
  EXPECT_HAS_ENTITY(index, Entity::Kind::kMacro, "", "MACRO", "", "snippet.cc",
                    1, 1);
  EXPECT_HAS_ENTITY(index, Entity::Kind::kFunction, "", "foo", "(int)",
                    "snippet.cc", 2, 4);
  EXPECT_HAS_ENTITY(index, Entity::Kind::kVariable, "", "bar", "", "snippet.cc",
                    2, 2);
  EXPECT_HAS_REFERENCE(index, Entity::Kind::kVariable, "", "bar", "",
                       "snippet.cc", 2, 2, "snippet.cc", 3, 3);
}

TEST(FrontendTest, MacroWrappedFunctionDefinition2) {
  auto index = IndexSnippet(
                   "#define MACRO(x, y, z) x y ## z\n"
                   "MACRO(void, foo, bar)() {\n"
                   "  return;\n"
                   "}\n")
                   ->Export();
  EXPECT_HAS_ENTITY(index, Entity::Kind::kMacro, "", "MACRO", "", "snippet.cc",
                    1, 1);
  EXPECT_HAS_ENTITY(index, Entity::Kind::kFunction, "", "foobar", "()",
                    "snippet.cc", 2, 4);
}

TEST(FrontendTest, VariadicFunctionDefinition) {
  auto index = IndexSnippet(
                   "void foo(int bar, ...) {\n"
                   "}")
                   ->Export();
  EXPECT_HAS_ENTITY(index, Entity::Kind::kVariable, "", "bar", "", "snippet.cc",
                    1, 1);
  EXPECT_HAS_ENTITY(index, Entity::Kind::kFunction, "", "foo", "(int, ...)",
                    "snippet.cc", 1, 2);
}

TEST(FrontendTest, CapturingLambdaDefinition) {
  auto index = IndexSnippet(
                   "void foo(int bar) {\n"
                   "  auto baz = [bar](int xof) {\n"
                   "    return bar + xof;\n"
                   "  };\n"
                   "}")
                   ->Export();
  EXPECT_HAS_ENTITY(index, Entity::Kind::kVariable, "", "bar", "", "snippet.cc",
                    1, 1);
  EXPECT_HAS_REFERENCE(index, Entity::Kind::kVariable, "", "bar", "",
                       "snippet.cc", 1, 1, "snippet.cc", 2, 2);
  EXPECT_HAS_REFERENCE(index, Entity::Kind::kVariable, "", "bar", "",
                       "snippet.cc", 1, 1, "snippet.cc", 3, 3);
  EXPECT_HAS_ENTITY(index, Entity::Kind::kFunction, "", "foo", "(int)",
                    "snippet.cc", 1, 5);
  EXPECT_HAS_ENTITY(index, Entity::Kind::kVariable, "", "baz", "", "snippet.cc",
                    2, 4);
  EXPECT_HAS_ENTITY(index, Entity::Kind::kVariable, "", "xof", "", "snippet.cc",
                    2, 2);
  EXPECT_HAS_REFERENCE(index, Entity::Kind::kVariable, "", "xof", "",
                       "snippet.cc", 2, 2, "snippet.cc", 3, 3);
  EXPECT_HAS_ENTITY(index, Entity::Kind::kFunction, "foo(int)::", "lambda",
                    "(int)", "snippet.cc", 2, 4);
  EXPECT_HAS_REFERENCE(index, Entity::Kind::kFunction, "foo(int)::", "lambda",
                       "(int)", "snippet.cc", 2, 4, "snippet.cc", 2, 4);
}

TEST(FrontendTest, NonCapturingLambdaDefinition) {
  auto index = IndexSnippet(
                   "void foo(int bar) {\n"
                   "  auto baz = [](int xof) {\n"
                   "    return xof;\n"
                   "  };\n"
                   "}")
                   ->Export();
  EXPECT_HAS_ENTITY(index, Entity::Kind::kVariable, "", "bar", "", "snippet.cc",
                    1, 1);
  EXPECT_HAS_ENTITY(index, Entity::Kind::kFunction, "", "foo", "(int)",
                    "snippet.cc", 1, 5);
  EXPECT_HAS_ENTITY(index, Entity::Kind::kVariable, "", "baz", "", "snippet.cc",
                    2, 4);
  EXPECT_HAS_ENTITY(index, Entity::Kind::kVariable, "", "xof", "", "snippet.cc",
                    2, 2);
  EXPECT_HAS_REFERENCE(index, Entity::Kind::kVariable, "", "xof", "",
                       "snippet.cc", 2, 2, "snippet.cc", 3, 3);
  EXPECT_HAS_ENTITY(index, Entity::Kind::kFunction, "foo(int)::", "lambda",
                    "(int)", "snippet.cc", 2, 4);
  EXPECT_HAS_REFERENCE(index, Entity::Kind::kFunction, "foo(int)::", "lambda",
                       "(int)", "snippet.cc", 2, 4, "snippet.cc", 2, 4);
}

TEST(FrontendTest, ClassDefinition) {
  auto index = IndexSnippet(
                   "class Foo;\n"
                   "class Foo {\n"
                   "  void bar();\n"
                   "  void baz() const;\n"
                   "};\n"
                   "void Foo::bar() {\n"
                   "}\n"
                   "void Foo::baz() const {\n"
                   "}\n"
                   "class Bar;\n")
                   ->Export();
  EXPECT_FALSE(IndexHasEntity(index, Entity::Kind::kClass, "", "Foo", "",
                              "snippet.cc", 1, 1));
  EXPECT_HAS_ENTITY(index, Entity::Kind::kClass, "", "Foo", "", "snippet.cc", 2,
                    5);
  EXPECT_HAS_ENTITY(index, Entity::Kind::kFunction, "Foo::", "bar", "()",
                    "snippet.cc", 6, 7);
  EXPECT_HAS_ENTITY(index, Entity::Kind::kFunction, "Foo::", "baz", "() const",
                    "snippet.cc", 8, 9);
  EXPECT_HAS_ENTITY(index, Entity::Kind::kClass, "", "Bar", "", "snippet.cc",
                    10, 10, /*is_incomplete=*/true);
}

TEST(FrontendTest, LocalClassDefinition) {
  auto index = IndexSnippet(
                   "void foo() {\n"
                   "  class Bar {\n"
                   "   public:\n"
                   "    void baz() {\n"
                   "    }\n"
                   "  } bar;\n"
                   "  bar.baz();\n"
                   "}")
                   ->Export();
  EXPECT_HAS_ENTITY(index, Entity::Kind::kFunction, "", "foo", "()",
                    "snippet.cc", 1, 8);
  EXPECT_HAS_ENTITY(index, Entity::Kind::kClass, "foo()::", "Bar", "",
                    "snippet.cc", 2, 6);
  EXPECT_HAS_REFERENCE(index, Entity::Kind::kClass, "foo()::", "Bar", "",
                       "snippet.cc", 2, 6, "snippet.cc", 2, 6);
  EXPECT_HAS_ENTITY(index, Entity::Kind::kFunction, "foo()::Bar::", "baz", "()",
                    "snippet.cc", 4, 5);
  EXPECT_HAS_REFERENCE(index, Entity::Kind::kFunction, "foo()::Bar::", "baz",
                       "()", "snippet.cc", 4, 5, "snippet.cc", 7, 7);
  EXPECT_HAS_ENTITY(index, Entity::Kind::kVariable, "", "bar", "", "snippet.cc",
                    2, 6);
  EXPECT_HAS_REFERENCE(index, Entity::Kind::kVariable, "", "bar", "",
                       "snippet.cc", 2, 6, "snippet.cc", 7, 7);
}

TEST(FrontendTest, Typedef) {
  auto index = IndexSnippet(
                   "typedef int foo;\n"
                   "typedef struct Bar{\n"
                   "} Baz;\n"
                   "Baz baz;\n")
                   ->Export();
  EXPECT_HAS_ENTITY(index, Entity::Kind::kClass, "", "Bar", "", "snippet.cc", 2,
                    3);
  EXPECT_HAS_REFERENCE(index, Entity::Kind::kClass, "", "Bar", "", "snippet.cc",
                       2, 3, "snippet.cc", 4, 4);
  EXPECT_HAS_ENTITY(index, Entity::Kind::kType, "", "Baz", "", "snippet.cc", 2,
                    3);
  EXPECT_HAS_REFERENCE(index, Entity::Kind::kType, "", "Baz", "", "snippet.cc",
                       2, 3, "snippet.cc", 4, 4);
  EXPECT_HAS_ENTITY(index, Entity::Kind::kVariable, "", "baz", "", "snippet.cc",
                    4, 4);
  EXPECT_HAS_ENTITY(index, Entity::Kind::kType, "", "foo", "", "snippet.cc", 1,
                    1);
}

TEST(FrontendTest, Using) {
  auto index = IndexSnippet(
                   "using foo = int;\n"
                   "using Bar = struct Baz{};\n"
                   "Bar bar;\n")
                   ->Export();
  EXPECT_HAS_ENTITY(index, Entity::Kind::kType, "", "Bar", "", "snippet.cc", 2,
                    2);
  EXPECT_HAS_REFERENCE(index, Entity::Kind::kType, "", "Bar", "", "snippet.cc",
                       2, 2, "snippet.cc", 3, 3);
  EXPECT_HAS_ENTITY(index, Entity::Kind::kClass, "", "Baz", "", "snippet.cc", 2,
                    2);
  EXPECT_HAS_REFERENCE(index, Entity::Kind::kClass, "", "Baz", "", "snippet.cc",
                       2, 2, "snippet.cc", 3, 3);
  EXPECT_HAS_ENTITY(index, Entity::Kind::kVariable, "", "bar", "", "snippet.cc",
                    3, 3);
  EXPECT_HAS_ENTITY(index, Entity::Kind::kType, "", "foo", "", "snippet.cc", 1,
                    1);
}

TEST(FrontendTest, TypeTemplateClass) {
  auto index = IndexSnippet(
                   "template <typename T, class S>\n"
                   "class Foo;\n"
                   "template <typename T, class S>\n"
                   "class Foo {\n"
                   "  void bar();\n"
                   "};\n"
                   "template <typename T, class S>\n"
                   "void Foo<T, S>::bar() {\n"
                   "}\n"
                   "Foo<int, int> baz;\n")
                   ->Export();
  EXPECT_FALSE(IndexHasEntity(index, Entity::Kind::kClass, "", "Foo", "<T, S>",
                              "snippet.cc", 1, 2));
  EXPECT_FALSE(IndexHasEntity(index, Entity::Kind::kType, "Foo::", "T", "",
                              "snippet.cc", 1, 1));
  EXPECT_FALSE(IndexHasEntity(index, Entity::Kind::kType, "Foo::", "S", "",
                              "snippet.cc", 1, 1));
  EXPECT_HAS_ENTITY(index, Entity::Kind::kClass, "", "Foo", "<T, S>",
                    "snippet.cc", 3, 6);
  EXPECT_HAS_ENTITY(index, Entity::Kind::kType, "Foo<T, S>::", "T", "",
                    "snippet.cc", 3, 3);
  EXPECT_HAS_ENTITY(index, Entity::Kind::kType, "Foo<T, S>::", "S", "",
                    "snippet.cc", 3, 3);
  EXPECT_HAS_ENTITY(index, Entity::Kind::kFunction, "Foo<T, S>::", "bar", "()",
                    "snippet.cc", 7, 9);
  EXPECT_HAS_ENTITY(index, Entity::Kind::kClass, "", "Foo", "<int, int>",
                    "snippet.cc", 3, 6, /*is_incomplete=*/false,
                    /*canonical_entity_id=*/
                    RequiredEntityId(index, Entity::Kind::kClass, "", "Foo",
                                     "<T, S>", "snippet.cc", 3, 6));
  EXPECT_HAS_REFERENCE(index, Entity::Kind::kClass, "", "Foo", "<int, int>",
                       "snippet.cc", 3, 6, "snippet.cc", 10, 10,
                       /*is_incomplete=*/false,
                       /*canonical_entity_id=*/
                       RequiredEntityId(index, Entity::Kind::kClass, "", "Foo",
                                        "<T, S>", "snippet.cc", 3, 6));
}

TEST(FrontendTest, UsingTypeTemplateClass) {
  auto index = IndexSnippet(
                   "class Foo;\n"
                   "template <typename T>\n"
                   "class Bar {};\n"
                   "using Baz = Bar<Foo*>;\n"
                   "Baz* baz;\n")
                   ->Export();
  EXPECT_HAS_ENTITY(index, Entity::Kind::kClass, "", "Foo", "", "snippet.cc", 1,
                    1, /*is_incomplete=*/true);
  EXPECT_HAS_REFERENCE(index, Entity::Kind::kClass, "", "Foo", "", "snippet.cc",
                       1, 1, "snippet.cc", 4, 4, /*is_incomplete=*/true);
  // TODO: Potential implicit reference.
  EXPECT_FALSE(IndexHasReference(index, Entity::Kind::kClass, "", "Foo", "",
                                 "snippet.cc", 1, 1, "snippet.cc", 5, 5,
                                 /*is_incomplete=*/true));
  EXPECT_HAS_ENTITY(index, Entity::Kind::kClass, "", "Bar", "<T>", "snippet.cc",
                    2, 3);
  EXPECT_HAS_ENTITY(index, Entity::Kind::kType, "Bar<T>::", "T", "",
                    "snippet.cc", 2, 2);
  EXPECT_HAS_ENTITY(index, Entity::Kind::kClass, "", "Bar", "<Foo *>",
                    "snippet.cc", 2, 3, /*is_incomplete=*/false,
                    /*canonical_entity_id=*/
                    RequiredEntityId(index, Entity::Kind::kClass, "", "Bar",
                                     "<T>", "snippet.cc", 2, 3));
  EXPECT_HAS_REFERENCE(index, Entity::Kind::kClass, "", "Bar", "<Foo *>",
                       "snippet.cc", 2, 3, "snippet.cc", 4, 4,
                       /*is_incomplete=*/false,
                       /*canonical_entity_id=*/
                       RequiredEntityId(index, Entity::Kind::kClass, "", "Bar",
                                        "<T>", "snippet.cc", 2, 3));
  EXPECT_HAS_REFERENCE(index, Entity::Kind::kClass, "", "Bar", "<Foo *>",
                       "snippet.cc", 2, 3, "snippet.cc", 5, 5,
                       /*is_incomplete=*/false,
                       /*canonical_entity_id=*/
                       RequiredEntityId(index, Entity::Kind::kClass, "", "Bar",
                                        "<T>", "snippet.cc", 2, 3));
  EXPECT_HAS_ENTITY(index, Entity::Kind::kType, "", "Baz", "", "snippet.cc", 4,
                    4);
  EXPECT_HAS_REFERENCE(index, Entity::Kind::kType, "", "Baz", "", "snippet.cc",
                       4, 4, "snippet.cc", 5, 5);
  EXPECT_HAS_ENTITY(index, Entity::Kind::kVariable, "", "baz", "", "snippet.cc",
                    5, 5);
}

TEST(FrontendTest, ValueTemplateClass) {
  auto index = IndexSnippet(
                   "template <char T, int S>\n"
                   "class Foo {\n"
                   "  void bar();\n"
                   "};\n"
                   "template <char T, int S>\n"
                   "void Foo<T, S>::bar() {\n"
                   "}\n"
                   "Foo<'A', 99> baz;\n")
                   ->Export();
  EXPECT_HAS_ENTITY(index, Entity::Kind::kClass, "", "Foo", "<char, int>",
                    "snippet.cc", 1, 4);
  EXPECT_HAS_ENTITY(index, Entity::Kind::kVariable, "Foo<char, int>::", "T", "",
                    "snippet.cc", 1, 1);
  EXPECT_HAS_ENTITY(index, Entity::Kind::kVariable, "Foo<char, int>::", "S", "",
                    "snippet.cc", 1, 1);
  EXPECT_HAS_ENTITY(index, Entity::Kind::kFunction, "Foo<char, int>::", "bar",
                    "()", "snippet.cc", 5, 7);

  // TODO: For consistency, we'd probably want the following
  // instead. However, due to the way that the AST handles template method
  // definitions, this isn't possible without manually walking the AST; and if
  // we add custom walking for template method definitions, we'd have to
  // remove the standard handling for other template types, and manually walk
  // those as well...

  // EXPECT_HAS_ENTITY(index, Entity::Kind::kVariable,
  //                            "Foo<char T, int S>::", "T", "", "snippet.cc",
  //                            5, 5));
  // EXPECT_HAS_REFERENCE(index, Entity::Kind::kVariable, "Foo<char
  // T, int S>::", "T", "", "snippet.cc", 5, 5, "snippet.cc", 6, 6));
  // EXPECT_HAS_ENTITY(index, Entity::Kind::kVariable,
  //                            "Foo<char T, int S>::", "S", "", "snippet.cc",
  //                            5, 5));
  // EXPECT_HAS_REFERENCE(index, Entity::Kind::kVariable, "Foo<char
  // T, int S>::", "S", "", "snippet.cc", 5, 5, "snippet.cc", 6, 6));

  EXPECT_HAS_ENTITY(index, Entity::Kind::kVariable, "", "S", "", "snippet.cc",
                    5, 5);
  EXPECT_HAS_REFERENCE(index, Entity::Kind::kVariable, "", "S", "",
                       "snippet.cc", 5, 5, "snippet.cc", 6, 6);
  EXPECT_HAS_ENTITY(index, Entity::Kind::kVariable, "", "T", "", "snippet.cc",
                    5, 5);
  EXPECT_HAS_REFERENCE(index, Entity::Kind::kVariable, "", "T", "",
                       "snippet.cc", 5, 5, "snippet.cc", 6, 6);
  EXPECT_HAS_ENTITY(index, Entity::Kind::kClass, "", "Foo", "<'A', 99>",
                    "snippet.cc", 1, 4, /*is_incomplete=*/false,
                    /*canonical_entity_id=*/
                    RequiredEntityId(index, Entity::Kind::kClass, "", "Foo",
                                     "<char, int>", "snippet.cc", 1, 4));
  EXPECT_HAS_REFERENCE(index, Entity::Kind::kClass, "", "Foo", "<'A', 99>",
                       "snippet.cc", 1, 4, "snippet.cc", 8, 8,
                       /*is_incomplete=*/false,
                       /*canonical_entity_id=*/
                       RequiredEntityId(index, Entity::Kind::kClass, "", "Foo",
                                        "<char, int>", "snippet.cc", 1, 4));
}

TEST(FrontendTest, TypeTemplateClassFullSpecialisation) {
  auto index = IndexSnippet(
                   "template <typename T>\n"
                   "class Foo {\n"
                   "};\n"
                   "template <>\n"
                   "class Foo<int> {\n"
                   "  int foo;\n"
                   "};\n")
                   ->Export();
  EXPECT_HAS_ENTITY(index, Entity::Kind::kClass, "", "Foo", "<T>", "snippet.cc",
                    1, 3);
  EXPECT_HAS_ENTITY(index, Entity::Kind::kType, "Foo<T>::", "T", "",
                    "snippet.cc", 1, 1);
  EXPECT_HAS_ENTITY(index, Entity::Kind::kClass, "", "Foo", "<int>",
                    "snippet.cc", 4, 7);
  EXPECT_HAS_ENTITY(index, Entity::Kind::kVariable, "Foo<int>::", "foo", "",
                    "snippet.cc", 6, 6);
}

TEST(FrontendTest, ValueTemplateClassFullSpecialisation) {
  auto index = IndexSnippet(
                   "template <int T>\n"
                   "class Foo {\n"
                   "};\n"
                   "template <>\n"
                   "class Foo<99> {\n"
                   "  int foo;\n"
                   "};\n")
                   ->Export();
  EXPECT_HAS_ENTITY(index, Entity::Kind::kClass, "", "Foo", "<int>",
                    "snippet.cc", 1, 3);
  EXPECT_HAS_ENTITY(index, Entity::Kind::kVariable, "Foo<int>::", "T", "",
                    "snippet.cc", 1, 1);
  EXPECT_HAS_ENTITY(index, Entity::Kind::kClass, "", "Foo", "<99>",
                    "snippet.cc", 4, 7);
  EXPECT_HAS_ENTITY(index, Entity::Kind::kVariable, "Foo<99>::", "foo", "",
                    "snippet.cc", 6, 6);
}

TEST(FrontendTest, TypeTemplateClassPartialSpecialisation) {
  auto index = IndexSnippet(
                   "template <typename T, typename S>\n"
                   "class Foo {\n"
                   "  S bar;\n"
                   "};\n"
                   "template <typename T>\n"
                   "class Foo<T, int> {\n"
                   "  T bar;\n"
                   "};\n")
                   ->Export();
  EXPECT_HAS_ENTITY(index, Entity::Kind::kClass, "", "Foo", "<T, S>",
                    "snippet.cc", 1, 4);
  EXPECT_HAS_ENTITY(index, Entity::Kind::kType, "Foo<T, S>::", "T", "",
                    "snippet.cc", 1, 1);
  EXPECT_HAS_ENTITY(index, Entity::Kind::kType, "Foo<T, S>::", "S", "",
                    "snippet.cc", 1, 1);
  EXPECT_HAS_ENTITY(index, Entity::Kind::kVariable, "Foo<T, S>::", "bar", "",
                    "snippet.cc", 3, 3);
  EXPECT_HAS_REFERENCE(index, Entity::Kind::kType, "Foo<T, S>::", "S", "",
                       "snippet.cc", 1, 1, "snippet.cc", 3, 3);
  EXPECT_HAS_ENTITY(index, Entity::Kind::kClass, "", "Foo", "<T, int>",
                    "snippet.cc", 5, 8);
  EXPECT_HAS_ENTITY(index, Entity::Kind::kType, "Foo<T, int>::", "T", "",
                    "snippet.cc", 5, 5);
  EXPECT_HAS_ENTITY(index, Entity::Kind::kVariable, "Foo<T, int>::", "bar", "",
                    "snippet.cc", 7, 7);
  EXPECT_HAS_REFERENCE(index, Entity::Kind::kType, "Foo<T, int>::", "T", "",
                       "snippet.cc", 5, 5, "snippet.cc", 7, 7);
}

TEST(FrontendTest, ValueTemplateClassPartialSpecialisation) {
  auto index = IndexSnippet(
                   "template <int T, char S>\n"
                   "class Foo {\n"
                   "  int bar = S;\n"
                   "};\n"
                   "template <int T>\n"
                   "class Foo<T, 'A'> {\n"
                   "  int bar = T;\n"
                   "};\n")
                   ->Export();
  EXPECT_HAS_ENTITY(index, Entity::Kind::kClass, "", "Foo", "<int, char>",
                    "snippet.cc", 1, 4);
  EXPECT_HAS_ENTITY(index, Entity::Kind::kVariable, "Foo<int, char>::", "T", "",
                    "snippet.cc", 1, 1);
  EXPECT_HAS_ENTITY(index, Entity::Kind::kVariable, "Foo<int, char>::", "S", "",
                    "snippet.cc", 1, 1);
  EXPECT_HAS_REFERENCE(index, Entity::Kind::kVariable, "Foo<int, char>::", "S",
                       "", "snippet.cc", 1, 1, "snippet.cc", 3, 3);
  EXPECT_HAS_ENTITY(index, Entity::Kind::kClass, "", "Foo", "<T, 'A'>",
                    "snippet.cc", 5, 8);
  EXPECT_HAS_ENTITY(index, Entity::Kind::kVariable, "Foo<T, 'A'>::", "bar", "",
                    "snippet.cc", 7, 7);
  EXPECT_HAS_REFERENCE(index, Entity::Kind::kVariable, "Foo<T, 'A'>::", "T", "",
                       "snippet.cc", 5, 5, "snippet.cc", 7, 7);
}

TEST(FrontendTest, TypeTemplateFunction) {
  auto index = IndexSnippet(
                   "template <typename T>\n"
                   "void foo(T bar) {\n"
                   "};\n"
                   "void baz() {\n"
                   "  foo(0);\n"
                   "}\n")
                   ->Export();
  EXPECT_HAS_ENTITY(index, Entity::Kind::kFunction, "", "foo", "<T>(T)",
                    "snippet.cc", 1, 3);
  EXPECT_HAS_ENTITY(index, Entity::Kind::kFunction, "", "foo", "<int>(int)",
                    "snippet.cc", 1, 3,
                    /*is_incomplete=*/false,
                    /*canonical_entity_id=*/
                    RequiredEntityId(index, Entity::Kind::kFunction, "", "foo",
                                     "<T>(T)", "snippet.cc", 1, 3));
  EXPECT_HAS_ENTITY(index, Entity::Kind::kType, "foo<T>(T)::", "T", "",
                    "snippet.cc", 1, 1);
  EXPECT_HAS_ENTITY(index, Entity::Kind::kVariable, "", "bar", "", "snippet.cc",
                    2, 2);
  EXPECT_HAS_REFERENCE(index, Entity::Kind::kType, "foo<T>(T)::", "T", "",
                       "snippet.cc", 1, 1, "snippet.cc", 2, 2);
  EXPECT_HAS_ENTITY(index, Entity::Kind::kFunction, "", "baz", "()",
                    "snippet.cc", 4, 6);
  EXPECT_HAS_REFERENCE(index, Entity::Kind::kFunction, "", "foo", "<int>(int)",
                       "snippet.cc", 1, 3, "snippet.cc", 5, 5,
                       /*is_incomplete=*/false,
                       /*canonical_entity_id=*/
                       RequiredEntityId(index, Entity::Kind::kFunction, "",
                                        "foo", "<T>(T)", "snippet.cc", 1, 3));
}

TEST(FrontendTest, ValueTemplateFunction) {
  auto index = IndexSnippet(
                   "template <int T>\n"
                   "int foo(int bar) {\n"
                   "  return bar + T;\n"
                   "};\n"
                   "void baz() {\n"
                   "  foo<88>(0);\n"
                   "}\n")
                   ->Export();
  EXPECT_HAS_ENTITY(index, Entity::Kind::kFunction, "", "foo", "<int>(int)",
                    "snippet.cc", 1, 4);
  EXPECT_HAS_ENTITY(index, Entity::Kind::kVariable, "foo<int>(int)::", "T", "",
                    "snippet.cc", 1, 1);
  EXPECT_HAS_REFERENCE(index, Entity::Kind::kVariable, "foo<int>(int)::", "T",
                       "", "snippet.cc", 1, 1, "snippet.cc", 3, 3);
  EXPECT_HAS_ENTITY(index, Entity::Kind::kVariable, "", "bar", "", "snippet.cc",
                    2, 2);
  EXPECT_HAS_REFERENCE(index, Entity::Kind::kVariable, "", "bar", "",
                       "snippet.cc", 2, 2, "snippet.cc", 3, 3);
  EXPECT_HAS_ENTITY(index, Entity::Kind::kFunction, "", "baz", "()",
                    "snippet.cc", 5, 7);
  EXPECT_HAS_ENTITY(index, Entity::Kind::kFunction, "", "foo", "<88>(int)",
                    "snippet.cc", 1, 4, /*is_incomplete=*/false,
                    /*canonical_entity_id=*/
                    RequiredEntityId(index, Entity::Kind::kFunction, "", "foo",
                                     "<int>(int)", "snippet.cc", 1, 4));
  EXPECT_HAS_REFERENCE(
      index, Entity::Kind::kFunction, "", "foo", "<88>(int)", "snippet.cc", 1,
      4, "snippet.cc", 6, 6, /*is_incomplete=*/false,
      /*canonical_entity_id=*/
      RequiredEntityId(index, Entity::Kind::kFunction, "", "foo", "<int>(int)",
                       "snippet.cc", 1, 4));
}

TEST(FrontendTest, TemplateTemplateFunction) {
  auto index = IndexSnippet(
                   "template <class T>\n"
                   "class Foo {\n"
                   "};\n"
                   "template <template<class> class S, class T>\n"
                   "void bar(const S<T>& baz) {\n"
                   "};\n"
                   "void qux() {\n"
                   "  Foo<int> foo;\n"
                   "  bar(foo);\n"
                   "}\n")
                   ->Export();
  EXPECT_HAS_ENTITY(index, Entity::Kind::kClass, "", "Foo", "<T>", "snippet.cc",
                    1, 3);
  EXPECT_HAS_ENTITY(index, Entity::Kind::kType, "Foo<T>::", "T", "",
                    "snippet.cc", 1, 1);
  EXPECT_HAS_ENTITY(index, Entity::Kind::kClass, "", "Foo", "<int>",
                    "snippet.cc", 1, 3,
                    /*is_incomplete=*/false, /*canonical_entity_id=*/
                    RequiredEntityId(index, Entity::Kind::kClass, "", "Foo",
                                     "<T>", "snippet.cc", 1, 3));
  EXPECT_HAS_REFERENCE(index, Entity::Kind::kClass, "", "Foo", "<int>",
                       "snippet.cc", 1, 3, "snippet.cc", 8, 8,
                       /*is_incomplete=*/false, /*canonical_entity_id=*/
                       RequiredEntityId(index, Entity::Kind::kClass, "", "Foo",
                                        "<T>", "snippet.cc", 1, 3));
  EXPECT_HAS_ENTITY(index, Entity::Kind::kFunction, "", "bar",
                    "<S, T>(const S<T> &)", "snippet.cc", 4, 6);
  EXPECT_HAS_ENTITY(index, Entity::Kind::kType,
                    "bar<S, T>(const S<T> &)::", "T", "", "snippet.cc", 4, 4);
  EXPECT_HAS_ENTITY(
      index, Entity::Kind::kFunction, "", "bar", "<Foo, int>(const Foo<int> &)",
      "snippet.cc", 4, 6,
      /*is_incomplete=*/false, /*canonical_entity_id=*/
      RequiredEntityId(index, Entity::Kind::kFunction, "", "bar",
                       "<S, T>(const S<T> &)", "snippet.cc", 4, 6));
  EXPECT_HAS_REFERENCE(
      index, Entity::Kind::kFunction, "", "bar", "<Foo, int>(const Foo<int> &)",
      "snippet.cc", 4, 6, "snippet.cc", 9, 9,
      /*is_incomplete=*/false, /*canonical_entity_id=*/
      RequiredEntityId(index, Entity::Kind::kFunction, "", "bar",
                       "<S, T>(const S<T> &)", "snippet.cc", 4, 6));
  EXPECT_HAS_ENTITY(index, Entity::Kind::kVariable, "", "baz", "", "snippet.cc",
                    5, 5);
  EXPECT_HAS_ENTITY(index, Entity::Kind::kVariable, "", "foo", "", "snippet.cc",
                    8, 8);
  EXPECT_HAS_REFERENCE(index, Entity::Kind::kVariable, "", "foo", "",
                       "snippet.cc", 8, 8, "snippet.cc", 9, 9);
  EXPECT_HAS_ENTITY(index, Entity::Kind::kFunction, "", "qux", "()",
                    "snippet.cc", 7, 10);
}

TEST(FrontendTest, TemplateParameterPackFunction) {
  auto index = IndexSnippet(
                   "template <class... T>\n"
                   "void foo(T... args) {\n"
                   "}\n"
                   "void bar() {\n"
                   "  foo(1, 2);\n"
                   "  foo(\"aaaaa\", 2, \"bbbb\");\n"
                   "}\n")
                   ->Export();
  EXPECT_HAS_ENTITY(
      index, Entity::Kind::kFunction, "", "foo",
      "<const char *, int, const char *>(const char *, int, const char *)",
      "snippet.cc", 1, 3, /*is_incomplete=*/false, /*canonical_entity_id=*/
      RequiredEntityId(index, Entity::Kind::kFunction, "", "foo",
                       "<T...>(T...)", "snippet.cc", 1, 3));
  EXPECT_HAS_REFERENCE(
      index, Entity::Kind::kFunction, "", "foo",
      "<const char *, int, const char *>(const char *, int, const char *)",
      "snippet.cc", 1, 3, "snippet.cc", 6, 6, /*is_incomplete=*/false,
      /*canonical_entity_id=*/
      RequiredEntityId(index, Entity::Kind::kFunction, "", "foo",
                       "<T...>(T...)", "snippet.cc", 1, 3));
  EXPECT_HAS_ENTITY(index, Entity::Kind::kFunction, "", "foo",
                    "<int, int>(int, int)", "snippet.cc", 1, 3,
                    /*is_incomplete=*/false, /*canonical_entity_id=*/
                    RequiredEntityId(index, Entity::Kind::kFunction, "", "foo",
                                     "<T...>(T...)", "snippet.cc", 1, 3));
  EXPECT_HAS_REFERENCE(
      index, Entity::Kind::kFunction, "", "foo", "<int, int>(int, int)",
      "snippet.cc", 1, 3, "snippet.cc", 5, 5, /*is_incomplete=*/false,
      /*canonical_entity_id=*/
      RequiredEntityId(index, Entity::Kind::kFunction, "", "foo",
                       "<T...>(T...)", "snippet.cc", 1, 3));
  EXPECT_HAS_ENTITY(index, Entity::Kind::kFunction, "", "foo", "<T...>(T...)",
                    "snippet.cc", 1, 3);
  EXPECT_HAS_ENTITY(index, Entity::Kind::kType, "foo<T...>(T...)::", "T", "",
                    "snippet.cc", 1, 1);
}

TEST(FrontendTest, FunctionScopedClassDefinition) {
  auto index = IndexSnippet(
                   "namespace foo {\n"
                   "void bar() {\n"
                   "  class Baz {};\n"
                   "};\n"
                   "}\n")
                   ->Export();
  EXPECT_HAS_ENTITY(index, Entity::Kind::kFunction, "foo::", "bar", "()",
                    "snippet.cc", 2, 4);
  EXPECT_HAS_ENTITY(index, Entity::Kind::kClass, "foo::bar()::", "Baz", "",
                    "snippet.cc", 3, 3);
}

TEST(FrontendTest, OperatorOverloads) {
  auto index = IndexSnippet(
                   "struct Foo {\n"
                   "  operator int() {\n"
                   "    return 0;\n"
                   "  }\n"
                   "  Foo& operator+=(const Foo& other) {\n"
                   "    return *this;\n"
                   "  }\n"
                   "};\n"
                   "int main() {\n"
                   "  Foo foo;\n"
                   "  Foo bar;\n"
                   "  foo += bar;\n"
                   "  return foo;\n"
                   "}\n")
                   ->Export();
  EXPECT_HAS_ENTITY(index, Entity::Kind::kClass, "", "Foo", "", "snippet.cc", 1,
                    8);
  EXPECT_HAS_REFERENCE(index, Entity::Kind::kClass, "", "Foo", "", "snippet.cc",
                       1, 8, "snippet.cc", 10, 10);
  EXPECT_HAS_REFERENCE(index, Entity::Kind::kClass, "", "Foo", "", "snippet.cc",
                       1, 8, "snippet.cc", 11, 11);
  EXPECT_HAS_ENTITY(index, Entity::Kind::kVariable, "", "bar", "", "snippet.cc",
                    11, 11);
  EXPECT_HAS_REFERENCE(index, Entity::Kind::kVariable, "", "bar", "",
                       "snippet.cc", 11, 11, "snippet.cc", 12, 12);
  EXPECT_HAS_ENTITY(index, Entity::Kind::kVariable, "", "foo", "", "snippet.cc",
                    10, 10);
  EXPECT_HAS_REFERENCE(index, Entity::Kind::kVariable, "", "foo", "",
                       "snippet.cc", 10, 10, "snippet.cc", 12, 12);
  EXPECT_HAS_REFERENCE(index, Entity::Kind::kVariable, "", "foo", "",
                       "snippet.cc", 10, 10, "snippet.cc", 13, 13);
  EXPECT_HAS_ENTITY(index, Entity::Kind::kFunction, "", "main", "()",
                    "snippet.cc", 9, 14);
  EXPECT_HAS_ENTITY(index, Entity::Kind::kVariable, "", "other", "",
                    "snippet.cc", 5, 5);
  EXPECT_HAS_ENTITY(index, Entity::Kind::kFunction, "Foo::", "operator int",
                    "()", "snippet.cc", 2, 4);
  EXPECT_HAS_REFERENCE(index, Entity::Kind::kFunction, "Foo::", "operator int",
                       "()", "snippet.cc", 2, 4, "snippet.cc", 13, 13);
  EXPECT_HAS_ENTITY(index, Entity::Kind::kFunction,
                    "Foo::", "operator+=", "(const Foo &)", "snippet.cc", 5, 7);
  EXPECT_HAS_REFERENCE(index, Entity::Kind::kFunction,
                       "Foo::", "operator+=", "(const Foo &)", "snippet.cc", 5,
                       7, "snippet.cc", 12, 12);
}

TEST(FrontendTest, NoIdentifierOperator) {
  // This causes some interesting stuff to happen with identifiers, as the
  // operator== doesn't have an identifier for the name. Not clear on why this
  // is different to the operator overloading testcase.
  auto index = IndexSnippet(
                   "template<typename T>\n"
                   "class Foo {};\n"
                   "template<typename T>\n"
                   "inline bool\n"
                   "operator==(const Foo<T>& lhs, const Foo<T>& rhs)\n"
                   "{ return &lhs == &rhs; }\n")
                   ->Export();
  EXPECT_HAS_ENTITY(index, Entity::Kind::kClass, "", "Foo", "<T>", "snippet.cc",
                    1, 2);
  EXPECT_HAS_ENTITY(index, Entity::Kind::kVariable, "", "lhs", "", "snippet.cc",
                    5, 5);
  EXPECT_HAS_REFERENCE(index, Entity::Kind::kVariable, "", "lhs", "",
                       "snippet.cc", 5, 5, "snippet.cc", 6, 6);
  EXPECT_HAS_ENTITY(index, Entity::Kind::kFunction, "",
                    "operator==", "<T>(const Foo<T> &, const Foo<T> &)",
                    "snippet.cc", 3, 6);
  EXPECT_HAS_ENTITY(index, Entity::Kind::kVariable, "", "rhs", "", "snippet.cc",
                    5, 5);
  EXPECT_HAS_REFERENCE(index, Entity::Kind::kVariable, "", "rhs", "",
                       "snippet.cc", 5, 5, "snippet.cc", 6, 6);
  EXPECT_HAS_ENTITY(index, Entity::Kind::kType, "Foo<T>::", "T", "",
                    "snippet.cc", 1, 1);
  EXPECT_HAS_ENTITY(index, Entity::Kind::kType,
                    "operator==<T>(const Foo<T> &, const Foo<T> &)::", "T", "",
                    "snippet.cc", 3, 3);
}

TEST(FrontendTest, PointerToStruct) {
  auto index = IndexSnippet(
                   "struct Foo {\n"
                   "  int field;\n"
                   "};\n"
                   "extern void f(const Foo*);\n"
                   "int main() {\n"
                   "  const Foo* const* foo_ptr = nullptr;\n"
                   "  f(*foo_ptr);\n"
                   "}\n")
                   ->Export();
  EXPECT_HAS_ENTITY(index, Entity::Kind::kClass, "", "Foo", "", "snippet.cc", 1,
                    3);
  EXPECT_HAS_REFERENCE(index, Entity::Kind::kClass, "", "Foo", "", "snippet.cc",
                       1, 3, "snippet.cc", 4, 4);
  EXPECT_HAS_REFERENCE(index, Entity::Kind::kClass, "", "Foo", "", "snippet.cc",
                       1, 3, "snippet.cc", 6, 6);
  EXPECT_HAS_ENTITY(index, Entity::Kind::kFunction, "", "f", "(const Foo *)",
                    "snippet.cc", 4, 4, /*is_incomplete=*/true);
  EXPECT_HAS_REFERENCE(index, Entity::Kind::kFunction, "", "f", "(const Foo *)",
                       "snippet.cc", 4, 4, "snippet.cc", 7, 7,
                       /*is_incomplete=*/true);
  EXPECT_HAS_ENTITY(index, Entity::Kind::kVariable, "", "foo_ptr", "",
                    "snippet.cc", 6, 6);
  EXPECT_HAS_REFERENCE(index, Entity::Kind::kVariable, "", "foo_ptr", "",
                       "snippet.cc", 6, 6, "snippet.cc", 7, 7);
  EXPECT_HAS_ENTITY(index, Entity::Kind::kFunction, "", "main", "()",
                    "snippet.cc", 5, 8);
  EXPECT_HAS_ENTITY(index, Entity::Kind::kVariable, "Foo::", "field", "",
                    "snippet.cc", 2, 2);
}

TEST(FrontendTest, PointerToType) {
  auto index = IndexSnippet(
                   "typedef struct FooStruct {} Foo;\n"
                   "using Bar = int;\n"
                   "int main() {\n"
                   "  Foo* foo_ptr = nullptr;\n"
                   "  Bar* bar_ptr = nullptr;\n"
                   "}\n")
                   ->Export();
  EXPECT_HAS_ENTITY(index, Entity::Kind::kType, "", "Bar", "", "snippet.cc", 2,
                    2);
  EXPECT_HAS_REFERENCE(index, Entity::Kind::kType, "", "Bar", "", "snippet.cc",
                       2, 2, "snippet.cc", 5, 5);
  EXPECT_HAS_ENTITY(index, Entity::Kind::kType, "", "Foo", "", "snippet.cc", 1,
                    1);
  EXPECT_HAS_REFERENCE(index, Entity::Kind::kType, "", "Foo", "", "snippet.cc",
                       1, 1, "snippet.cc", 4, 4);
  EXPECT_HAS_ENTITY(index, Entity::Kind::kClass, "", "FooStruct", "",
                    "snippet.cc", 1, 1);
  EXPECT_HAS_REFERENCE(index, Entity::Kind::kClass, "", "FooStruct", "",
                       "snippet.cc", 1, 1, "snippet.cc", 4, 4);
  EXPECT_HAS_ENTITY(index, Entity::Kind::kVariable, "", "bar_ptr", "",
                    "snippet.cc", 5, 5);
  EXPECT_HAS_ENTITY(index, Entity::Kind::kVariable, "", "foo_ptr", "",
                    "snippet.cc", 4, 4);
  EXPECT_HAS_ENTITY(index, Entity::Kind::kFunction, "", "main", "()",
                    "snippet.cc", 3, 6);
}

TEST(FrontendTest, ReferenceToStruct) {
  auto index = IndexSnippet(
                   "struct Foo {\n"
                   "  int field;\n"
                   "};\n"
                   "extern void f(Foo&);\n"
                   "int main() {\n"
                   "  Foo foo;\n"
                   "  Foo& foo_ref = foo;\n"
                   "  f(foo_ref);\n"
                   "}\n")
                   ->Export();
  EXPECT_HAS_ENTITY(index, Entity::Kind::kClass, "", "Foo", "", "snippet.cc", 1,
                    3);
  EXPECT_HAS_REFERENCE(index, Entity::Kind::kClass, "", "Foo", "", "snippet.cc",
                       1, 3, "snippet.cc", 6, 6);
  EXPECT_HAS_ENTITY(index, Entity::Kind::kFunction, "", "f", "(Foo &)",
                    "snippet.cc", 4, 4, /*is_incomplete=*/true);
  EXPECT_HAS_REFERENCE(index, Entity::Kind::kFunction, "", "f", "(Foo &)",
                       "snippet.cc", 4, 4, "snippet.cc", 8, 8,
                       /*is_incomplete=*/true);
  EXPECT_HAS_ENTITY(index, Entity::Kind::kVariable, "", "foo", "", "snippet.cc",
                    6, 6);
  EXPECT_HAS_REFERENCE(index, Entity::Kind::kVariable, "", "foo", "",
                       "snippet.cc", 6, 6, "snippet.cc", 7, 7);
  EXPECT_HAS_ENTITY(index, Entity::Kind::kVariable, "", "foo_ref", "",
                    "snippet.cc", 7, 7);
  EXPECT_HAS_REFERENCE(index, Entity::Kind::kVariable, "", "foo_ref", "",
                       "snippet.cc", 7, 7, "snippet.cc", 8, 8);
  EXPECT_HAS_ENTITY(index, Entity::Kind::kFunction, "", "main", "()",
                    "snippet.cc", 5, 9);
  EXPECT_HAS_ENTITY(index, Entity::Kind::kVariable, "Foo::", "field", "",
                    "snippet.cc", 2, 2);
}

TEST(FrontendTest, ReferenceToReturnType) {
  auto index = IndexSnippet(
                   "struct Foo {\n"
                   "  int bar;\n"
                   "};\n"
                   "Foo* baz() {\n"
                   "  return nullptr;\n"
                   "}\n")
                   ->Export();
  EXPECT_HAS_ENTITY(index, Entity::Kind::kClass, "", "Foo", "", "snippet.cc", 1,
                    3);
  EXPECT_HAS_REFERENCE(index, Entity::Kind::kClass, "", "Foo", "", "snippet.cc",
                       1, 3, "snippet.cc", 4, 4);
  EXPECT_HAS_ENTITY(index, Entity::Kind::kFunction, "", "baz", "()",
                    "snippet.cc", 4, 6);
  EXPECT_HAS_ENTITY(index, Entity::Kind::kVariable, "Foo::", "bar", "",
                    "snippet.cc", 2, 2);
}

TEST(FrontendTest, ReferenceToSizeof) {
  auto index = IndexSnippet(
                   "struct Foo {\n"
                   "  int bar;\n"
                   "} foo;\n"
                   "int size_1 = (int)sizeof(struct Foo);\n"
                   "int size_2 = (int)sizeof(foo);\n")
                   ->Export();
  EXPECT_HAS_ENTITY(index, Entity::Kind::kClass, "", "Foo", "", "snippet.cc", 1,
                    3);
  EXPECT_HAS_ENTITY(index, Entity::Kind::kVariable, "Foo::", "bar", "",
                    "snippet.cc", 2, 2);
  EXPECT_HAS_REFERENCE(index, Entity::Kind::kClass, "", "Foo", "", "snippet.cc",
                       1, 3, "snippet.cc", 1, 3);
  EXPECT_HAS_REFERENCE(index, Entity::Kind::kClass, "", "Foo", "", "snippet.cc",
                       1, 3, "snippet.cc", 4, 4);
  EXPECT_HAS_ENTITY(index, Entity::Kind::kVariable, "", "foo", "", "snippet.cc",
                    1, 3);
  EXPECT_HAS_REFERENCE(index, Entity::Kind::kVariable, "", "foo", "",
                       "snippet.cc", 1, 3, "snippet.cc", 5, 5);
  EXPECT_HAS_ENTITY(index, Entity::Kind::kVariable, "", "size_1", "",
                    "snippet.cc", 4, 4);
  EXPECT_HAS_ENTITY(index, Entity::Kind::kVariable, "", "size_2", "",
                    "snippet.cc", 5, 5);
}

TEST(FrontendTest, DeletedConstructor) {
  auto index = IndexSnippet(
                   "class Foo {\n"
                   "  Foo(const Foo&) = delete;\n"
                   "  Foo(Foo&&) = delete;\n"
                   "  Foo& operator=(const Foo&) = delete;\n"
                   "};\n")
                   ->Export();
  EXPECT_HAS_ENTITY(index, Entity::Kind::kClass, "", "Foo", "", "snippet.cc", 1,
                    5);
  EXPECT_FALSE(IndexHasEntity(index, Entity::Kind::kFunction, "Foo::", "Foo",
                              "(Foo &&)", "snippet.cc", 3, 3,
                              /*is_incomplete=*/true));
  EXPECT_FALSE(IndexHasEntity(index, Entity::Kind::kFunction, "Foo::", "Foo",
                              "(const Foo &)", "snippet.cc", 2, 2,
                              /*is_incomplete=*/true));
  EXPECT_FALSE(IndexHasEntity(index, Entity::Kind::kFunction,
                              "Foo::", "operator=", "(const Foo &)",
                              "snippet.cc", 4, 4, /*is_incomplete=*/true));
}

TEST(FrontendTest, PureVirtualMethod) {
  auto index = IndexSnippet(
                   "class Foo {\n"
                   "  virtual void Bar() = 0;\n"
                   "};\n")
                   ->Export();
  EXPECT_HAS_ENTITY(index, Entity::Kind::kClass, "", "Foo", "", "snippet.cc", 1,
                    3);
  // pure virtual methods are complete, even though they have no body.
  EXPECT_HAS_ENTITY(index, Entity::Kind::kFunction, "Foo::", "Bar", "()",
                    "snippet.cc", 2, 2);
}

TEST(FrontendTest, Builtin) {
  auto index = IndexSnippet(
                   "int foo(int value) {\n"
                   "  __builtin_trap();\n"
                   "  __builtin_trap();\n"
                   "}\n")
                   ->Export();
  EXPECT_HAS_ENTITY(index, Entity::Kind::kFunction, "", "__builtin_trap", "()",
                    "snippet.cc", 2, 2);
  EXPECT_HAS_REFERENCE(index, Entity::Kind::kFunction, "", "__builtin_trap",
                       "()", "snippet.cc", 2, 2, "snippet.cc", 2, 2);
  EXPECT_HAS_REFERENCE(index, Entity::Kind::kFunction, "", "__builtin_trap",
                       "()", "snippet.cc", 2, 2, "snippet.cc", 3, 3);
  EXPECT_HAS_ENTITY(index, Entity::Kind::kFunction, "", "foo", "(int)",
                    "snippet.cc", 1, 4);
  EXPECT_HAS_ENTITY(index, Entity::Kind::kVariable, "", "value", "",
                    "snippet.cc", 1, 1);
}

TEST(FrontendTest, RecursiveTemplateInstantiation) {
  auto index = IndexSnippet(
                   "volatile int bar = 0;\n"
                   "template <typename... Args> struct Foo;\n"
                   "template <>\n"
                   "struct Foo<> {\n"
                   "  static void foo() {};\n"
                   "};\n"
                   "template <typename... Args>\n"
                   "struct Foo<int, Args...> {\n"
                   "  static void foo(int arg, Args... args) {\n"
                   "    bar += arg;\n"
                   "    Foo<Args...>::foo(args...);\n"
                   "  }\n"
                   "};\n"
                   "template <typename... Args>\n"
                   "struct Foo<char, Args...> {\n"
                   "  static void foo(char arg, Args... args) {\n"
                   "    bar += arg;\n"
                   "    Foo<Args...>::foo(args...);\n"
                   "  }\n"
                   "};\n"
                   "template <typename Arg, typename... Args>\n"
                   "struct Foo<Arg, Args...> {\n"
                   "  static void foo(Arg arg, Args... args) {\n"
                   "    Foo<Args...>::foo(args...);\n"
                   "  }\n"
                   "};\n"
                   "int main() {\n"
                   "  Foo<int, char, int, char>::foo(1, 'b', 3, 'd');\n"
                   "}\n")
                   ->Export();
  // First the expected classes
  EXPECT_HAS_ENTITY(index, Entity::Kind::kClass, "", "Foo", "<Args...>",
                    "snippet.cc", 2, 2,
                    /*is_incomplete=*/true);
  EXPECT_HAS_ENTITY(index, Entity::Kind::kClass, "", "Foo", "<>", "snippet.cc",
                    3, 6);
  EXPECT_HAS_ENTITY(index, Entity::Kind::kClass, "", "Foo", "<int, Args...>",
                    "snippet.cc", 7, 13);
  EXPECT_HAS_ENTITY(index, Entity::Kind::kClass, "", "Foo", "<char, Args...>",
                    "snippet.cc", 14, 20);
  EXPECT_HAS_ENTITY(index, Entity::Kind::kClass, "", "Foo", "<Arg, Args...>",
                    "snippet.cc", 21, 26);

  // And the expected functions.
  EXPECT_HAS_ENTITY(index, Entity::Kind::kFunction, "Foo<>::", "foo", "()",
                    "snippet.cc", 5, 5);
  EXPECT_HAS_ENTITY(index, Entity::Kind::kFunction,
                    "Foo<char, Args...>::", "foo", "(char, Args...)",
                    "snippet.cc", 16, 19);
  EXPECT_HAS_ENTITY(index, Entity::Kind::kFunction,
                    "Foo<int, Args...>::", "foo", "(int, Args...)",
                    "snippet.cc", 9, 12);
  EXPECT_HAS_ENTITY(index, Entity::Kind::kFunction,
                    "Foo<Arg, Args...>::", "foo", "(Arg, Args...)",
                    "snippet.cc", 23, 25);

  // Then make sure we get the final instantiation function with the correct
  // parameter types.
  EXPECT_HAS_ENTITY(index, Entity::Kind::kFunction,
                    "Foo<int, char, int, char>::", "foo",
                    "(int, char, int, char)", "snippet.cc", 9, 12,
                    /*is_incomplete=*/false,
                    /*canonical_entity_id=*/
                    RequiredEntityId(index, Entity::Kind::kFunction,
                                     "Foo<int, Args...>::", "foo",
                                     "(int, Args...)", "snippet.cc", 9, 12));
  EXPECT_HAS_REFERENCE(
      index, Entity::Kind::kFunction, "Foo<int, char, int, char>::", "foo",
      "(int, char, int, char)", "snippet.cc", 9, 12, "snippet.cc", 28, 28,
      /*is_incomplete=*/false,
      /*canonical_entity_id=*/
      RequiredEntityId(index, Entity::Kind::kFunction, "Foo<int, Args...>::",
                       "foo", "(int, Args...)", "snippet.cc", 9, 12));
}

TEST(FrontendTest, IncompleteTemplate) {
  auto index = IndexSnippet(
                   "template <class T>\n"
                   "class Foo;\n"
                   "using Bar = Foo<int>;\n"
                   "template <class T>\n"
                   "class Foo {\n"
                   " public:\n"
                   "  int baz_;\n"
                   "};\n"
                   "Bar bar;\n")
                   ->Export();
  EXPECT_HAS_ENTITY(index, Entity::Kind::kClass, "", "Foo", "<T>", "snippet.cc",
                    4, 8);
  EXPECT_HAS_REFERENCE(index, Entity::Kind::kClass, "", "Foo", "<T>",
                       "snippet.cc", 4, 8, "snippet.cc", 3, 3);
  EXPECT_HAS_REFERENCE(index, Entity::Kind::kClass, "", "Foo", "<T>",
                       "snippet.cc", 4, 8, "snippet.cc", 9, 9);

  EXPECT_HAS_ENTITY(index, Entity::Kind::kClass, "", "Foo", "<int>",
                    "snippet.cc", 4, 8,
                    /*is_incomplete=*/false,
                    /*canonical_entity_id=*/
                    RequiredEntityId(index, Entity::Kind::kClass, "", "Foo",
                                     "<T>", "snippet.cc", 4, 8));
  EXPECT_HAS_REFERENCE(index, Entity::Kind::kClass, "", "Foo", "<int>",
                       "snippet.cc", 4, 8, "snippet.cc", 3, 3,
                       /*is_incomplete=*/false,
                       /*canonical_entity_id=*/
                       RequiredEntityId(index, Entity::Kind::kClass, "", "Foo",
                                        "<T>", "snippet.cc", 4, 8));
  EXPECT_HAS_REFERENCE(index, Entity::Kind::kClass, "", "Foo", "<int>",
                       "snippet.cc", 4, 8, "snippet.cc", 9, 9,
                       /*is_incomplete=*/false,
                       /*canonical_entity_id=*/
                       RequiredEntityId(index, Entity::Kind::kClass, "", "Foo",
                                        "<T>", "snippet.cc", 4, 8));

  EXPECT_HAS_ENTITY(index, Entity::Kind::kType, "", "Bar", "", "snippet.cc", 3,
                    3);
  EXPECT_HAS_REFERENCE(index, Entity::Kind::kType, "", "Bar", "", "snippet.cc",
                       3, 3, "snippet.cc", 9, 9);
}

TEST(FrontendTest, ConstrainedSpecialization) {
  auto index = IndexSnippet(
                   "template <class T>\n"
                   "class Foo {};\n"
                   "template <class T>\n"
                   "class Bar {};\n"
                   "template <class T>\n"
                   "class Bar<Foo<T>> {};\n")
                   ->Export();
  EXPECT_HAS_ENTITY(index, Entity::Kind::kClass, "", "Bar", "<Foo<T>>",
                    "snippet.cc", 5, 6);
  EXPECT_HAS_ENTITY(index, Entity::Kind::kClass, "", "Bar", "<T>", "snippet.cc",
                    3, 4);
  EXPECT_HAS_ENTITY(index, Entity::Kind::kClass, "", "Foo", "<T>", "snippet.cc",
                    1, 2);
  EXPECT_HAS_ENTITY(index, Entity::Kind::kType, "Bar<Foo<T>>::", "T", "",
                    "snippet.cc", 5, 5);
  EXPECT_HAS_ENTITY(index, Entity::Kind::kType, "Bar<T>::", "T", "",
                    "snippet.cc", 3, 3);
  EXPECT_HAS_ENTITY(index, Entity::Kind::kType, "Foo<T>::", "T", "",
                    "snippet.cc", 1, 1);
}

TEST(FrontendTest, MoreTemplateSpecialization) {
  auto index = IndexSnippet(
                   "template <typename S, typename T>\n"
                   "class Foo {};\n"
                   "template <typename S, typename T>\n"
                   "using Bar = Foo<S, T>;\n"
                   "template <typename S, typename T>\n"
                   "using Baz = Foo<Bar<S, bool>, T>;\n"
                   "Bar<int, char> bar;\n"
                   "Baz<int, char> baz;\n")
                   ->Export();
  // Check that the baseline template entities exist
  EXPECT_HAS_ENTITY(index, Entity::Kind::kClass, "", "Foo", "<S, T>",
                    "snippet.cc", 1, 2);
  EXPECT_HAS_REFERENCE(index, Entity::Kind::kClass, "", "Foo", "<S, T>",
                       "snippet.cc", 1, 2, "snippet.cc", 4, 4);
  EXPECT_HAS_REFERENCE(index, Entity::Kind::kClass, "", "Foo", "<S, T>",
                       "snippet.cc", 1, 2, "snippet.cc", 6, 6);
  // TODO: Maybe add these if we have implicit reference support.
  EXPECT_FALSE(IndexHasReference(index, Entity::Kind::kClass, "", "Foo",
                                 "<S, T>", "snippet.cc", 1, 2, "snippet.cc", 7,
                                 7));
  EXPECT_FALSE(IndexHasReference(index, Entity::Kind::kClass, "", "Foo",
                                 "<S, T>", "snippet.cc", 1, 2, "snippet.cc", 8,
                                 8));

  EXPECT_HAS_ENTITY(index, Entity::Kind::kType, "", "Bar", "<S, T>",
                    "snippet.cc", 4, 4);
  EXPECT_HAS_REFERENCE(index, Entity::Kind::kType, "", "Bar", "<S, T>",
                       "snippet.cc", 4, 4, "snippet.cc", 6, 6);
  EXPECT_HAS_REFERENCE(index, Entity::Kind::kType, "", "Bar", "<S, T>",
                       "snippet.cc", 4, 4, "snippet.cc", 7, 7);
  // TODO: Maybe add these if we have implicit reference support.
  EXPECT_FALSE(IndexHasReference(index, Entity::Kind::kType, "", "Bar",
                                 "<S, T>", "snippet.cc", 4, 4, "snippet.cc", 8,
                                 8));

  EXPECT_HAS_ENTITY(index, Entity::Kind::kType, "", "Baz", "<S, T>",
                    "snippet.cc", 6, 6);
  EXPECT_HAS_REFERENCE(index, Entity::Kind::kType, "", "Baz", "<S, T>",
                       "snippet.cc", 6, 6, "snippet.cc", 8, 8);

  // Check that the correct specializations of Foo exist
  EXPECT_HAS_ENTITY(index, Entity::Kind::kClass, "", "Foo", "<int, char>",
                    "snippet.cc", 1, 2,
                    /*is_incomplete=*/false, /*canonical_entity_id=*/
                    RequiredEntityId(index, Entity::Kind::kClass, "", "Foo",
                                     "<S, T>", "snippet.cc", 1, 2));
  EXPECT_HAS_REFERENCE(index, Entity::Kind::kClass, "", "Foo", "<int, char>",
                       "snippet.cc", 1, 2, "snippet.cc", 7, 7,
                       /*is_incomplete=*/false, /*canonical_entity_id=*/
                       RequiredEntityId(index, Entity::Kind::kClass, "", "Foo",
                                        "<S, T>", "snippet.cc", 1, 2));
  EXPECT_HAS_ENTITY(index, Entity::Kind::kClass, "", "Foo",
                    "<Foo<int, bool>, char>", "snippet.cc", 1, 2,
                    /*is_incomplete=*/false, /*canonical_entity_id=*/
                    RequiredEntityId(index, Entity::Kind::kClass, "", "Foo",
                                     "<S, T>", "snippet.cc", 1, 2));
  EXPECT_HAS_REFERENCE(index, Entity::Kind::kClass, "", "Foo",
                       "<Foo<int, bool>, char>", "snippet.cc", 1, 2,
                       "snippet.cc", 8, 8,
                       /*is_incomplete=*/false, /*canonical_entity_id=*/
                       RequiredEntityId(index, Entity::Kind::kClass, "", "Foo",
                                        "<S, T>", "snippet.cc", 1, 2));
  // Note: These entities no longer exist, because they're also implicit. Maybe
  // we want them, but it's unclear how we'd be able to use them without the
  // implicit references.
  // EXPECT_HAS_ENTITY(index, Entity::Kind::kClass, "", "Foo", "<int, bool>",
  //                   "snippet.cc", 1, 2);
  // EXPECT_HAS_REFERENCE(index, Entity::Kind::kClass, "", "Foo", "<int, bool>",
  //                      "snippet.cc", 1, 2, "snippet.cc", 8, 8);
}

TEST(FrontendTest, FormatTemplateArgumentsOne) {
  auto index = IndexSnippet(
                   "template <typename... Args> class Foo {};\n"
                   "Foo<int, int, int> foo;\n")
                   ->Export();
  // Base templates.
  EXPECT_HAS_ENTITY(index, Entity::Kind::kClass, "", "Foo", "<Args...>",
                    "snippet.cc", 1, 1);
  EXPECT_HAS_REFERENCE(index, Entity::Kind::kClass, "", "Foo", "<Args...>",
                       "snippet.cc", 1, 1, "snippet.cc", 2, 2);

  // Specializations.
  EXPECT_HAS_ENTITY(index, Entity::Kind::kClass, "", "Foo", "<int, int, int>",
                    "snippet.cc", 1, 1,
                    /*is_incomplete=*/false,
                    /*canonical_entity_id=*/
                    RequiredEntityId(index, Entity::Kind::kClass, "", "Foo",
                                     "<Args...>", "snippet.cc", 1, 1));
  EXPECT_HAS_REFERENCE(index, Entity::Kind::kClass, "", "Foo",
                       "<int, int, int>", "snippet.cc", 1, 1, "snippet.cc", 2,
                       2,
                       /*is_incomplete=*/false,
                       /*canonical_entity_id=*/
                       RequiredEntityId(index, Entity::Kind::kClass, "", "Foo",
                                        "<Args...>", "snippet.cc", 1, 1));
}

TEST(FrontendTest, FormatTemplateArgumentsTwo) {
  auto index = IndexSnippet(
                   "template <typename T> class Foo {};\n"
                   "template <typename T> class Bar {};\n"
                   "template <typename T> using Baz = Foo<Bar<T>>;\n"
                   "Baz<int> baz;\n")
                   ->Export();
  // Base templates.
  EXPECT_HAS_ENTITY(index, Entity::Kind::kClass, "", "Foo", "<T>", "snippet.cc",
                    1, 1);
  EXPECT_HAS_REFERENCE(index, Entity::Kind::kClass, "", "Foo", "<T>",
                       "snippet.cc", 1, 1, "snippet.cc", 3, 3);
  EXPECT_HAS_ENTITY(index, Entity::Kind::kClass, "", "Bar", "<T>", "snippet.cc",
                    2, 2);
  EXPECT_HAS_REFERENCE(index, Entity::Kind::kClass, "", "Bar", "<T>",
                       "snippet.cc", 2, 2, "snippet.cc", 3, 3);
  EXPECT_HAS_ENTITY(index, Entity::Kind::kType, "", "Baz", "<T>", "snippet.cc",
                    3, 3);

  // Specializations.
  // TODO: If we add implicit references at some point, we should
  // reintroduce these two as implicit references.
  EXPECT_FALSE(IndexHasEntity(index, Entity::Kind::kClass, "", "Bar", "<int>",
                              "snippet.cc", 2, 2));
  EXPECT_FALSE(IndexHasReference(index, Entity::Kind::kClass, "", "Bar",
                                 "<int>", "snippet.cc", 2, 2, "snippet.cc", 4,
                                 4));
  EXPECT_HAS_ENTITY(index, Entity::Kind::kClass, "", "Foo", "<Bar<int>>",
                    "snippet.cc", 1, 1,
                    /*is_incomplete=*/false,
                    /*canonical_entity_id=*/
                    RequiredEntityId(index, Entity::Kind::kClass, "", "Foo",
                                     "<T>", "snippet.cc", 1, 1));
  EXPECT_HAS_REFERENCE(index, Entity::Kind::kClass, "", "Foo", "<Bar<int>>",
                       "snippet.cc", 1, 1, "snippet.cc", 4, 4,
                       /*is_incomplete=*/false,
                       /*canonical_entity_id=*/
                       RequiredEntityId(index, Entity::Kind::kClass, "", "Foo",
                                        "<T>", "snippet.cc", 1, 1));
  EXPECT_HAS_ENTITY(index, Entity::Kind::kType, "", "Baz", "<int>",
                    "snippet.cc", 3, 3,
                    /*is_incomplete=*/false,
                    /*canonical_entity_id=*/
                    RequiredEntityId(index, Entity::Kind::kType, "", "Baz",
                                     "<T>", "snippet.cc", 3, 3));
  EXPECT_HAS_REFERENCE(index, Entity::Kind::kType, "", "Baz", "<int>",
                       "snippet.cc", 3, 3, "snippet.cc", 4, 4,
                       /*is_incomplete=*/false,
                       /*canonical_entity_id=*/
                       RequiredEntityId(index, Entity::Kind::kType, "", "Baz",
                                        "<T>", "snippet.cc", 3, 3));
}

TEST(FrontendTest, FormatTemplateArgumentsThree) {
  auto index = IndexSnippet(
                   "template <typename T, typename S> class Foo {};\n"
                   "template <typename T> using Bar = Foo<T, int>;\n"
                   "Bar<char> bar;\n")
                   ->Export();
  // Base templates.
  EXPECT_HAS_ENTITY(index, Entity::Kind::kClass, "", "Foo", "<T, S>",
                    "snippet.cc", 1, 1);
  EXPECT_HAS_REFERENCE(index, Entity::Kind::kClass, "", "Foo", "<T, S>",
                       "snippet.cc", 1, 1, "snippet.cc", 2, 2);
  EXPECT_HAS_ENTITY(index, Entity::Kind::kType, "", "Bar", "<T>", "snippet.cc",
                    2, 2);
  EXPECT_HAS_REFERENCE(index, Entity::Kind::kType, "", "Bar", "<T>",
                       "snippet.cc", 2, 2, "snippet.cc", 3, 3);

  // Specializations.
  EXPECT_HAS_ENTITY(index, Entity::Kind::kClass, "", "Foo", "<char, int>",
                    "snippet.cc", 1, 1,
                    /*is_incomplete=*/false,
                    /*canonical_entity_id=*/
                    RequiredEntityId(index, Entity::Kind::kClass, "", "Foo",
                                     "<T, S>", "snippet.cc", 1, 1));
  EXPECT_HAS_REFERENCE(index, Entity::Kind::kClass, "", "Foo", "<char, int>",
                       "snippet.cc", 1, 1, "snippet.cc", 3, 3,
                       /*is_incomplete=*/false,
                       /*canonical_entity_id=*/
                       RequiredEntityId(index, Entity::Kind::kClass, "", "Foo",
                                        "<T, S>", "snippet.cc", 1, 1));
  EXPECT_HAS_ENTITY(index, Entity::Kind::kType, "", "Bar", "<char>",
                    "snippet.cc", 2, 2,
                    /*is_incomplete=*/false,
                    /*canonical_entity_id=*/
                    RequiredEntityId(index, Entity::Kind::kType, "", "Bar",
                                     "<T>", "snippet.cc", 2, 2));
  EXPECT_HAS_REFERENCE(index, Entity::Kind::kType, "", "Bar", "<char>",
                       "snippet.cc", 2, 2, "snippet.cc", 3, 3,
                       /*is_incomplete=*/false,
                       /*canonical_entity_id=*/
                       RequiredEntityId(index, Entity::Kind::kType, "", "Bar",
                                        "<T>", "snippet.cc", 2, 2));
}

TEST(FrontendTest, EvenMoreTemplates) {
  auto index = IndexSnippet(
                   "template <typename A, typename B> class Foo { };\n"
                   "template <typename A, typename B> using Bar = Foo<B, A>;\n"
                   "\n"
                   "template <typename... Args> class Baz {};\n"
                   "template <typename A, typename B> using Brrrr = Foo<Baz<A, "
                   "char, int>, B>;\n"
                   "\n"
                   "int main() {\n"
                   "    Bar<int, char> bar;\n"
                   "    Brrrr<int, char> brrrr;\n"
                   "}\n")
                   ->Export();
  // Base templates.
  EXPECT_HAS_ENTITY(index, Entity::Kind::kClass, "", "Foo", "<A, B>",
                    "snippet.cc", 1, 1);
  EXPECT_HAS_REFERENCE(index, Entity::Kind::kClass, "", "Foo", "<A, B>",
                       "snippet.cc", 1, 1, "snippet.cc", 2, 2);
  EXPECT_HAS_REFERENCE(index, Entity::Kind::kClass, "", "Foo", "<A, B>",
                       "snippet.cc", 1, 1, "snippet.cc", 5, 5);
  EXPECT_HAS_ENTITY(index, Entity::Kind::kType, "", "Bar", "<A, B>",
                    "snippet.cc", 2, 2);
  EXPECT_HAS_REFERENCE(index, Entity::Kind::kType, "", "Bar", "<A, B>",
                       "snippet.cc", 2, 2, "snippet.cc", 8, 8);
  EXPECT_HAS_ENTITY(index, Entity::Kind::kClass, "", "Baz", "<Args...>",
                    "snippet.cc", 4, 4);
  EXPECT_HAS_REFERENCE(index, Entity::Kind::kClass, "", "Baz", "<Args...>",
                       "snippet.cc", 4, 4, "snippet.cc", 5, 5);
  EXPECT_HAS_ENTITY(index, Entity::Kind::kType, "", "Brrrr", "<A, B>",
                    "snippet.cc", 5, 5);
  EXPECT_HAS_REFERENCE(index, Entity::Kind::kType, "", "Brrrr", "<A, B>",
                       "snippet.cc", 5, 5, "snippet.cc", 9, 9);

  // Specializations/instantiations.
  EXPECT_HAS_ENTITY(index, Entity::Kind::kType, "", "Bar", "<int, char>",
                    "snippet.cc", 2, 2,
                    /*is_incomplete=*/false,
                    /*canonical_entity_id=*/
                    RequiredEntityId(index, Entity::Kind::kType, "", "Bar",
                                     "<A, B>", "snippet.cc", 2, 2));
  EXPECT_HAS_REFERENCE(index, Entity::Kind::kType, "", "Bar", "<int, char>",
                       "snippet.cc", 2, 2, "snippet.cc", 8, 8,
                       /*is_incomplete=*/false,
                       /*canonical_entity_id=*/
                       RequiredEntityId(index, Entity::Kind::kType, "", "Bar",
                                        "<A, B>", "snippet.cc", 2, 2));
  EXPECT_HAS_ENTITY(index, Entity::Kind::kClass, "", "Foo", "<char, int>",
                    "snippet.cc", 1, 1, /*is_incomplete=*/false,
                    /*canonical_entity_id=*/
                    RequiredEntityId(index, Entity::Kind::kClass, "", "Foo",
                                     "<A, B>", "snippet.cc", 1, 1));
  EXPECT_HAS_REFERENCE(index, Entity::Kind::kClass, "", "Foo", "<char, int>",
                       "snippet.cc", 1, 1, "snippet.cc", 8, 8,
                       /*is_incomplete=*/false,
                       /*canonical_entity_id=*/
                       RequiredEntityId(index, Entity::Kind::kClass, "", "Foo",
                                        "<A, B>", "snippet.cc", 1, 1));

  EXPECT_HAS_ENTITY(index, Entity::Kind::kType, "", "Brrrr", "<int, char>",
                    "snippet.cc", 5, 5, /*is_incomplete=*/false,
                    /*canonical_entity_id=*/
                    RequiredEntityId(index, Entity::Kind::kType, "", "Brrrr",
                                     "<A, B>", "snippet.cc", 5, 5));
  EXPECT_HAS_REFERENCE(index, Entity::Kind::kType, "", "Brrrr", "<int, char>",
                       "snippet.cc", 5, 5, "snippet.cc", 9, 9,
                       /*is_incomplete=*/false,
                       /*canonical_entity_id=*/
                       RequiredEntityId(index, Entity::Kind::kType, "", "Brrrr",
                                        "<A, B>", "snippet.cc", 5, 5));
  EXPECT_HAS_ENTITY(index, Entity::Kind::kClass, "", "Foo",
                    "<Baz<int, char, int>, char>", "snippet.cc", 1, 1,
                    /*is_incomplete=*/false,
                    /*canonical_entity_id=*/
                    RequiredEntityId(index, Entity::Kind::kClass, "", "Foo",
                                     "<A, B>", "snippet.cc", 1, 1));
  EXPECT_HAS_REFERENCE(index, Entity::Kind::kClass, "", "Foo",
                       "<Baz<int, char, int>, char>", "snippet.cc", 1, 1,
                       "snippet.cc", 9, 9, /*is_incomplete=*/false,
                       /*canonical_entity_id=*/
                       RequiredEntityId(index, Entity::Kind::kClass, "", "Foo",
                                        "<A, B>", "snippet.cc", 1, 1));
}

TEST(FrontendTest, QualifiedTypeSpecialization) {
  auto index = IndexSnippet(
                   "template <typename A> class Foo { };\n"
                   "template <typename A> class Foo<const A> { };\n"
                   "template <typename A> class Foo<volatile A> { };\n"
                   "Foo<int> foo;\n"
                   "Foo<const int> const_foo;\n"
                   "Foo<volatile int> volatile_foo;\n")
                   ->Export();
  EXPECT_HAS_ENTITY(index, Entity::Kind::kClass, "", "Foo", "<A>", "snippet.cc",
                    1, 1);
  EXPECT_HAS_REFERENCE(index, Entity::Kind::kClass, "", "Foo", "<A>",
                       "snippet.cc", 1, 1, "snippet.cc", 4, 4);
  EXPECT_HAS_ENTITY(index, Entity::Kind::kClass, "", "Foo", "<int>",
                    "snippet.cc", 1, 1, /*is_incomplete=*/false,
                    /*canonical_entity_id=*/
                    RequiredEntityId(index, Entity::Kind::kClass, "", "Foo",
                                     "<A>", "snippet.cc", 1, 1));
  EXPECT_HAS_REFERENCE(index, Entity::Kind::kClass, "", "Foo", "<int>",
                       "snippet.cc", 1, 1, "snippet.cc", 4, 4,
                       /*is_incomplete=*/false,
                       /*canonical_entity_id=*/
                       RequiredEntityId(index, Entity::Kind::kClass, "", "Foo",
                                        "<A>", "snippet.cc", 1, 1));

  EXPECT_HAS_ENTITY(index, Entity::Kind::kClass, "", "Foo", "<const A>",
                    "snippet.cc", 2, 2);
  EXPECT_HAS_REFERENCE(index, Entity::Kind::kClass, "", "Foo", "<const A>",
                       "snippet.cc", 2, 2, "snippet.cc", 5, 5);
  EXPECT_HAS_ENTITY(index, Entity::Kind::kClass, "", "Foo", "<const int>",
                    "snippet.cc", 2, 2, /*is_incomplete=*/false,
                    /*canonical_entity_id=*/
                    RequiredEntityId(index, Entity::Kind::kClass, "", "Foo",
                                     "<const A>", "snippet.cc", 2, 2));
  EXPECT_HAS_REFERENCE(index, Entity::Kind::kClass, "", "Foo", "<const int>",
                       "snippet.cc", 2, 2, "snippet.cc", 5, 5,
                       /*is_incomplete=*/false,
                       /*canonical_entity_id=*/
                       RequiredEntityId(index, Entity::Kind::kClass, "", "Foo",
                                        "<const A>", "snippet.cc", 2, 2));

  EXPECT_HAS_ENTITY(index, Entity::Kind::kClass, "", "Foo", "<volatile A>",
                    "snippet.cc", 3, 3);
  EXPECT_HAS_REFERENCE(index, Entity::Kind::kClass, "", "Foo", "<volatile A>",
                       "snippet.cc", 3, 3, "snippet.cc", 6, 6);
  EXPECT_HAS_ENTITY(index, Entity::Kind::kClass, "", "Foo", "<volatile int>",
                    "snippet.cc", 3, 3, /*is_incomplete=*/false,
                    /*canonical_entity_id=*/
                    RequiredEntityId(index, Entity::Kind::kClass, "", "Foo",
                                     "<volatile A>", "snippet.cc", 3, 3));
  EXPECT_HAS_REFERENCE(index, Entity::Kind::kClass, "", "Foo", "<volatile int>",
                       "snippet.cc", 3, 3, "snippet.cc", 6, 6,
                       /*is_incomplete=*/false,
                       /*canonical_entity_id=*/
                       RequiredEntityId(index, Entity::Kind::kClass, "", "Foo",
                                        "<volatile A>", "snippet.cc", 3, 3));
}

TEST(FrontendTest, QualifiedTypeSpecializationTwo) {
  auto index = IndexSnippet(
                   "template <typename A> class Foo { };\n"
                   "template <typename A> class Foo<const A&> { };\n"
                   "template <typename A> class Foo<const A* const> { };\n"
                   "template <typename A> class Foo<volatile A&&> { };\n"
                   "Foo<int> foo;\n"
                   "Foo<const int&> const_foo;\n"
                   "Foo<const int* const> const_const_foo;\n"
                   "Foo<volatile int&&> volatile_foo;\n")
                   ->Export();
  EXPECT_HAS_ENTITY(index, Entity::Kind::kClass, "", "Foo", "<A>", "snippet.cc",
                    1, 1);
  EXPECT_HAS_REFERENCE(index, Entity::Kind::kClass, "", "Foo", "<A>",
                       "snippet.cc", 1, 1, "snippet.cc", 5, 5);
  EXPECT_HAS_ENTITY(index, Entity::Kind::kClass, "", "Foo", "<int>",
                    "snippet.cc", 1, 1, /*is_incomplete=*/false,
                    /*canonical_entity_id=*/
                    RequiredEntityId(index, Entity::Kind::kClass, "", "Foo",
                                     "<A>", "snippet.cc", 1, 1));
  EXPECT_HAS_REFERENCE(index, Entity::Kind::kClass, "", "Foo", "<int>",
                       "snippet.cc", 1, 1, "snippet.cc", 5, 5,
                       /*is_incomplete=*/false,
                       /*canonical_entity_id=*/
                       RequiredEntityId(index, Entity::Kind::kClass, "", "Foo",
                                        "<A>", "snippet.cc", 1, 1));

  EXPECT_HAS_ENTITY(index, Entity::Kind::kClass, "", "Foo", "<const A &>",
                    "snippet.cc", 2, 2);
  EXPECT_HAS_REFERENCE(index, Entity::Kind::kClass, "", "Foo", "<const A &>",
                       "snippet.cc", 2, 2, "snippet.cc", 6, 6);
  EXPECT_HAS_ENTITY(index, Entity::Kind::kClass, "", "Foo", "<const int &>",
                    "snippet.cc", 2, 2, /*is_incomplete=*/false,
                    /*canonical_entity_id=*/
                    RequiredEntityId(index, Entity::Kind::kClass, "", "Foo",
                                     "<const A &>", "snippet.cc", 2, 2));
  EXPECT_HAS_REFERENCE(index, Entity::Kind::kClass, "", "Foo", "<const int &>",
                       "snippet.cc", 2, 2, "snippet.cc", 6, 6,
                       /*is_incomplete=*/false,
                       /*canonical_entity_id=*/
                       RequiredEntityId(index, Entity::Kind::kClass, "", "Foo",
                                        "<const A &>", "snippet.cc", 2, 2));

  EXPECT_HAS_ENTITY(index, Entity::Kind::kClass, "", "Foo", "<const A *const>",
                    "snippet.cc", 3, 3);
  EXPECT_HAS_REFERENCE(index, Entity::Kind::kClass, "", "Foo",
                       "<const A *const>", "snippet.cc", 3, 3, "snippet.cc", 7,
                       7);
  EXPECT_HAS_ENTITY(index, Entity::Kind::kClass, "", "Foo",
                    "<const int *const>", "snippet.cc", 3, 3,
                    /*is_incomplete=*/false,
                    /*canonical_entity_id=*/
                    RequiredEntityId(index, Entity::Kind::kClass, "", "Foo",
                                     "<const A *const>", "snippet.cc", 3, 3));
  EXPECT_HAS_REFERENCE(
      index, Entity::Kind::kClass, "", "Foo", "<const int *const>",
      "snippet.cc", 3, 3, "snippet.cc", 7, 7, /*is_incomplete=*/false,
      /*canonical_entity_id=*/
      RequiredEntityId(index, Entity::Kind::kClass, "", "Foo",
                       "<const A *const>", "snippet.cc", 3, 3));

  EXPECT_HAS_ENTITY(index, Entity::Kind::kClass, "", "Foo", "<volatile A &&>",
                    "snippet.cc", 4, 4);
  EXPECT_HAS_REFERENCE(index, Entity::Kind::kClass, "", "Foo",
                       "<volatile A &&>", "snippet.cc", 4, 4, "snippet.cc", 8,
                       8);
  EXPECT_HAS_ENTITY(index, Entity::Kind::kClass, "", "Foo", "<volatile int &&>",
                    "snippet.cc", 4, 4, /*is_incomplete=*/false,
                    /*canonical_entity_id=*/
                    RequiredEntityId(index, Entity::Kind::kClass, "", "Foo",
                                     "<volatile A &&>", "snippet.cc", 4, 4));
  EXPECT_HAS_REFERENCE(index, Entity::Kind::kClass, "", "Foo",
                       "<volatile int &&>", "snippet.cc", 4, 4, "snippet.cc", 8,
                       8, /*is_incomplete=*/false,
                       /*canonical_entity_id=*/
                       RequiredEntityId(index, Entity::Kind::kClass, "", "Foo",
                                        "<volatile A &&>", "snippet.cc", 4, 4));
}

TEST(FrontendTest, QualifiedTypeSpecializationThree) {
  auto index = IndexSnippet(
                   "template <typename A> class Foo { };\n"
                   "template <typename A> class Foo<const A[1]> { };\n"
                   "Foo<const int[1]> foo_1;\n")
                   ->Export();
  EXPECT_HAS_ENTITY(index, Entity::Kind::kClass, "", "Foo", "<A>", "snippet.cc",
                    1, 1);
  EXPECT_HAS_ENTITY(index, Entity::Kind::kClass, "", "Foo", "<const A[1]>",
                    "snippet.cc", 2, 2);
  // TODO: Figure out why clang finds the correct specialization
  // for the cases in FrontendTest.QualifiedTypeSpecialization and
  // FrontendTest.QualifiedTypeSpecializationTwo but not here. This reference
  // incorrectly goes to the base template instead.
  //
  // EXPECT_HAS_REFERENCE(index, Entity::Kind::kClass, "", "Foo",
  //                      "<const A[1]>", "snippet.cc", 2, 2, "snippet.cc",
  //                      3, 3);
  EXPECT_HAS_ENTITY(index, Entity::Kind::kClass, "", "Foo", "<const int[1]>",
                    "snippet.cc", 2, 2, /*is_incomplete=*/false,
                    /*canonical_entity_id=*/
                    RequiredEntityId(index, Entity::Kind::kClass, "", "Foo",
                                     "<const A[1]>", "snippet.cc", 2, 2));
  EXPECT_HAS_REFERENCE(index, Entity::Kind::kClass, "", "Foo", "<const int[1]>",
                       "snippet.cc", 2, 2, "snippet.cc", 3, 3,
                       /*is_incomplete=*/false,
                       /*canonical_entity_id=*/
                       RequiredEntityId(index, Entity::Kind::kClass, "", "Foo",
                                        "<const A[1]>", "snippet.cc", 2, 2));
}

TEST(FrontendTest, UsingSpecialization) {
  auto index = IndexSnippet(
                   "template <typename A> class Foo;\n"
                   "using Bar = Foo<int>;\n"
                   "template <typename A> class Foo {};\n")
                   ->Export();
  EXPECT_HAS_ENTITY(index, Entity::Kind::kType, "", "Bar", "", "snippet.cc", 2,
                    2);
  EXPECT_HAS_ENTITY(index, Entity::Kind::kClass, "", "Foo", "<A>", "snippet.cc",
                    3, 3);
  EXPECT_HAS_ENTITY(index, Entity::Kind::kType, "Foo<A>::", "A", "",
                    "snippet.cc", 3, 3);
  EXPECT_HAS_ENTITY(index, Entity::Kind::kClass, "", "Foo", "<int>",
                    "snippet.cc", 3, 3, /*is_incomplete=*/false,
                    /*canonical_entity_id=*/
                    RequiredEntityId(index, Entity::Kind::kClass, "", "Foo",
                                     "<A>", "snippet.cc", 3, 3));
  EXPECT_HAS_REFERENCE(index, Entity::Kind::kClass, "", "Foo", "<int>",
                       "snippet.cc", 3, 3, "snippet.cc", 2, 2,
                       /*is_incomplete=*/false,
                       /*canonical_entity_id=*/
                       RequiredEntityId(index, Entity::Kind::kClass, "", "Foo",
                                        "<A>", "snippet.cc", 3, 3));
}

TEST(FrontendTest, UsingSpecializationTwo) {
  auto index = IndexSnippet(
                   "template <typename A> class Foo;\n"
                   "using Bar = Foo<int>;\n"
                   "template <typename A> class Foo {};\n"
                   "template <> class Foo<int> {};\n")
                   ->Export();
  EXPECT_HAS_ENTITY(index, Entity::Kind::kType, "", "Bar", "", "snippet.cc", 2,
                    2);
  EXPECT_HAS_ENTITY(index, Entity::Kind::kClass, "", "Foo", "<A>", "snippet.cc",
                    3, 3);
  EXPECT_HAS_ENTITY(index, Entity::Kind::kType, "Foo<A>::", "A", "",
                    "snippet.cc", 3, 3);
  EXPECT_HAS_ENTITY(index, Entity::Kind::kClass, "", "Foo", "<int>",
                    "snippet.cc", 4, 4);
  EXPECT_HAS_REFERENCE(index, Entity::Kind::kClass, "", "Foo", "<int>",
                       "snippet.cc", 4, 4, "snippet.cc", 2, 2);
}

TEST(FrontendTest, BooleanParameter) {
  auto index = IndexSnippet("void foo(bool bar) {}\n")->Export();
  EXPECT_HAS_ENTITY(index, Entity::Kind::kVariable, "", "bar", "", "snippet.cc",
                    1, 1);
  EXPECT_HAS_ENTITY(index, Entity::Kind::kFunction, "", "foo", "(bool)",
                    "snippet.cc", 1, 1);
}

TEST(FrontendTest, BooleanTemplate) {
  auto index = IndexSnippet("template <bool T> class Foo {};\n")->Export();
  EXPECT_HAS_ENTITY(index, Entity::Kind::kClass, "", "Foo", "<bool>",
                    "snippet.cc", 1, 1);
  EXPECT_HAS_ENTITY(index, Entity::Kind::kVariable, "Foo<bool>::", "T", "",
                    "snippet.cc", 1, 1);
}

TEST(FrontendTest, InheritanceReference) {
  auto index = IndexSnippet(
                   "class Base {};\n"
                   "class Child : public Base {};\n")
                   ->Export();
  EXPECT_HAS_ENTITY(index, Entity::Kind::kClass, "", "Base", "", "snippet.cc",
                    1, 1);
  EXPECT_HAS_REFERENCE(index, Entity::Kind::kClass, "", "Base", "",
                       "snippet.cc", 1, 1, "snippet.cc", 2, 2);
  EXPECT_HAS_ENTITY(index, Entity::Kind::kClass, "", "Child", "", "snippet.cc",
                    2, 2);
}

TEST(FrontendTest, MemberTemplateInstantiation) {
  auto index = IndexSnippet(
                   "class Foo {\n"
                   " public:\n"
                   "  template <typename T>\n"
                   "  static T GetA();\n"
                   "  int GetB() {\n"
                   "    return Foo::GetA<int>();\n"
                   "  }\n"
                   "};\n"
                   "template <typename T>\n"
                   "T Foo::GetA() {\n"
                   "  return 99;\n"
                   "}\n"
                   "int main() {\n"
                   "  Foo foo;\n"
                   "  return foo.GetB() + Foo::GetA<unsigned int>();\n"
                   "}\n")
                   ->Export();
  EXPECT_HAS_ENTITY(index, Entity::Kind::kClass, "", "Foo", "", "snippet.cc", 1,
                    8);
  EXPECT_HAS_REFERENCE(index, Entity::Kind::kClass, "", "Foo", "", "snippet.cc",
                       1, 8, "snippet.cc", 14, 14);
  EXPECT_HAS_ENTITY(index, Entity::Kind::kFunction, "Foo::", "GetA", "<T>()",
                    "snippet.cc", 9, 12);
  EXPECT_HAS_ENTITY(index, Entity::Kind::kFunction, "Foo::", "GetA", "<int>()",
                    "snippet.cc", 9, 12, /*is_incomplete=*/false,
                    /*canonical_entity_id=*/
                    RequiredEntityId(index, Entity::Kind::kFunction, "Foo::",
                                     "GetA", "<T>()", "snippet.cc", 9, 12));
  EXPECT_HAS_REFERENCE(
      index, Entity::Kind::kFunction, "Foo::", "GetA", "<int>()", "snippet.cc",
      9, 12, "snippet.cc", 6, 6, /*is_incomplete=*/false,
      /*canonical_entity_id=*/
      RequiredEntityId(index, Entity::Kind::kFunction, "Foo::", "GetA", "<T>()",
                       "snippet.cc", 9, 12));
  EXPECT_HAS_ENTITY(
      index, Entity::Kind::kFunction, "Foo::", "GetA", "<unsigned int>()",
      "snippet.cc", 9, 12, /*is_incomplete=*/false,
      /*canonical_entity_id=*/
      RequiredEntityId(index, Entity::Kind::kFunction, "Foo::", "GetA", "<T>()",
                       "snippet.cc", 9, 12));
  EXPECT_HAS_REFERENCE(
      index, Entity::Kind::kFunction, "Foo::", "GetA", "<unsigned int>()",
      "snippet.cc", 9, 12, "snippet.cc", 15, 15, /*is_incomplete=*/false,
      /*canonical_entity_id=*/
      RequiredEntityId(index, Entity::Kind::kFunction, "Foo::", "GetA", "<T>()",
                       "snippet.cc", 9, 12));
  EXPECT_HAS_ENTITY(index, Entity::Kind::kFunction, "Foo::", "GetB", "()",
                    "snippet.cc", 5, 7);
  EXPECT_HAS_REFERENCE(index, Entity::Kind::kFunction, "Foo::", "GetB", "()",
                       "snippet.cc", 5, 7, "snippet.cc", 15, 15);
  EXPECT_HAS_ENTITY(index, Entity::Kind::kType, "Foo::GetA<T>()::", "T", "",
                    "snippet.cc", 9, 9);
  EXPECT_HAS_REFERENCE(index, Entity::Kind::kType, "Foo::GetA<T>()::", "T", "",
                       "snippet.cc", 9, 9, "snippet.cc", 10, 10);
  EXPECT_HAS_ENTITY(index, Entity::Kind::kFunction, "", "main", "()",
                    "snippet.cc", 13, 16);
  EXPECT_HAS_ENTITY(index, Entity::Kind::kVariable, "", "foo", "", "snippet.cc",
                    14, 14);
  EXPECT_HAS_REFERENCE(index, Entity::Kind::kVariable, "", "foo", "",
                       "snippet.cc", 14, 14, "snippet.cc", 15, 15);
}

TEST(FrontendTest, ClassTemplateMemberReference) {
  auto index = IndexSnippet(
                   "template <typename T>\n"
                   "class Foo {\n"
                   " public:\n"
                   "  static T GetA();\n"
                   "  static const T kConstant = 99;\n"
                   "};\n"
                   "template <typename T>\n"
                   "T Foo<T>::GetA() {\n"
                   "  return 99;\n"
                   "}\n"
                   "int main() {\n"
                   "  int result = Foo<int>::kConstant;\n"
                   "  return result + Foo<int>::GetA();\n"
                   "}\n")
                   ->Export();
  EXPECT_HAS_ENTITY(index, Entity::Kind::kClass, "", "Foo", "<T>", "snippet.cc",
                    1, 6);
  EXPECT_HAS_ENTITY(index, Entity::Kind::kClass, "", "Foo", "<int>",
                    "snippet.cc", 1, 6, /*is_incomplete=*/false,
                    /*canonical_entity_id=*/
                    RequiredEntityId(index, Entity::Kind::kClass, "", "Foo",
                                     "<T>", "snippet.cc", 1, 6));
  EXPECT_HAS_REFERENCE(index, Entity::Kind::kClass, "", "Foo", "<int>",
                       "snippet.cc", 1, 6, "snippet.cc", 13, 13,
                       /*is_incomplete=*/false,
                       /*canonical_entity_id=*/
                       RequiredEntityId(index, Entity::Kind::kClass, "", "Foo",
                                        "<T>", "snippet.cc", 1, 6));
  EXPECT_HAS_ENTITY(index, Entity::Kind::kFunction, "Foo<T>::", "GetA", "()",
                    "snippet.cc", 7, 10);
  EXPECT_HAS_ENTITY(index, Entity::Kind::kVariable, "Foo<T>::", "kConstant", "",
                    "snippet.cc", 5, 5);
  EXPECT_HAS_ENTITY(index, Entity::Kind::kFunction, "Foo<int>::", "GetA", "()",
                    "snippet.cc", 7, 10, /*is_incomplete=*/false,
                    /*canonical_entity_id=*/
                    RequiredEntityId(index, Entity::Kind::kFunction, "Foo<T>::",
                                     "GetA", "()", "snippet.cc", 7, 10));
  EXPECT_HAS_REFERENCE(
      index, Entity::Kind::kFunction, "Foo<int>::", "GetA", "()", "snippet.cc",
      7, 10, "snippet.cc", 13, 13,
      /*is_incomplete=*/false, /*canonical_entity_id=*/
      RequiredEntityId(index, Entity::Kind::kFunction, "Foo<T>::", "GetA", "()",
                       "snippet.cc", 7, 10));
  EXPECT_HAS_ENTITY(
      index, Entity::Kind::kVariable, "Foo<int>::", "kConstant", "",
      "snippet.cc", 5, 5, /*is_incomplete=*/false, /*canonical_entity_id=*/
      RequiredEntityId(index, Entity::Kind::kVariable, "Foo<T>::", "kConstant",
                       "", "snippet.cc", 5, 5));
  EXPECT_HAS_REFERENCE(
      index, Entity::Kind::kVariable, "Foo<int>::", "kConstant", "",
      "snippet.cc", 5, 5, "snippet.cc", 12, 12, /*is_incomplete=*/false,
      /*canonical_entity_id=*/
      RequiredEntityId(index, Entity::Kind::kVariable, "Foo<T>::", "kConstant",
                       "", "snippet.cc", 5, 5));
  EXPECT_HAS_ENTITY(index, Entity::Kind::kFunction, "", "main", "()",
                    "snippet.cc", 11, 14);
  EXPECT_HAS_ENTITY(index, Entity::Kind::kVariable, "", "result", "",
                    "snippet.cc", 12, 12);
  EXPECT_HAS_REFERENCE(index, Entity::Kind::kVariable, "", "result", "",
                       "snippet.cc", 12, 12, "snippet.cc", 13, 13);
}

TEST(FrontendTest, AnonymousStructMemberCollision) {
  auto index = IndexSnippet(
                   "struct {\n"
                   " int bar;\n"
                   "} foo;\n"
                   "struct {\n"
                   " int bar;\n"
                   "} baz;\n"
                   "int main() {\n"
                   "  return foo.bar + baz.bar;\n"
                   "}\n")
                   ->Export();
  EXPECT_HAS_ENTITY(index, Entity::Kind::kClass, "", "(anonymous struct)", "",
                    "snippet.cc", 1, 3);
  EXPECT_HAS_REFERENCE(index, Entity::Kind::kClass, "", "(anonymous struct)",
                       "", "snippet.cc", 1, 3, "snippet.cc", 1, 3);
  EXPECT_HAS_ENTITY(index, Entity::Kind::kClass, "", "(anonymous struct)", "",
                    "snippet.cc", 4, 6);
  EXPECT_HAS_REFERENCE(index, Entity::Kind::kClass, "", "(anonymous struct)",
                       "", "snippet.cc", 4, 6, "snippet.cc", 4, 6);
  EXPECT_HAS_ENTITY(index, Entity::Kind::kVariable, "", "baz", "", "snippet.cc",
                    4, 6);
  EXPECT_HAS_REFERENCE(index, Entity::Kind::kVariable, "", "baz", "",
                       "snippet.cc", 4, 6, "snippet.cc", 8, 8);
  EXPECT_HAS_ENTITY(index, Entity::Kind::kVariable, "", "foo", "", "snippet.cc",
                    1, 3);
  EXPECT_HAS_REFERENCE(index, Entity::Kind::kVariable, "", "foo", "",
                       "snippet.cc", 1, 3, "snippet.cc", 8, 8);
  EXPECT_HAS_ENTITY(index, Entity::Kind::kFunction, "", "main", "()",
                    "snippet.cc", 7, 9);

  // BUG: b/416218844 - These two entities have identical names.
  EXPECT_HAS_ENTITY(index, Entity::Kind::kVariable,
                    "(anonymous struct)::", "bar", "", "snippet.cc", 2, 2);
  EXPECT_HAS_REFERENCE(index, Entity::Kind::kVariable,
                       "(anonymous struct)::", "bar", "", "snippet.cc", 2, 2,
                       "snippet.cc", 8, 8);
  EXPECT_HAS_ENTITY(index, Entity::Kind::kVariable,
                    "(anonymous struct)::", "bar", "", "snippet.cc", 5, 5);
  EXPECT_HAS_REFERENCE(index, Entity::Kind::kVariable,
                       "(anonymous struct)::", "bar", "", "snippet.cc", 5, 5,
                       "snippet.cc", 8, 8);
}

TEST(FrontendTest, ImplicitThisOverload) {
  auto index = IndexSnippet(
                   "class Test {\n"
                   " public:\n"
                   "  int foo(int a) && { return a; }\n"
                   "  const char* foo(int a) volatile & { \n"
                   "    return \"A\";\n"
                   "  }\n"
                   "  int* foo(int a) const & { return nullptr; }\n"
                   "};\n"
                   "int main() {\n"
                   "  return Test().foo(1);\n"
                   "}\n")
                   ->Export();
  EXPECT_HAS_ENTITY(index, Entity::Kind::kVariable, "", "a", "", "snippet.cc",
                    3, 3);
  EXPECT_HAS_REFERENCE(index, Entity::Kind::kVariable, "", "a", "",
                       "snippet.cc", 3, 3, "snippet.cc", 3, 3);
  EXPECT_HAS_ENTITY(index, Entity::Kind::kVariable, "", "a", "", "snippet.cc",
                    4, 4);

  EXPECT_HAS_ENTITY(index, Entity::Kind::kFunction, "Test::", "foo", "(int) &&",
                    "snippet.cc", 3, 3);
  EXPECT_HAS_REFERENCE(index, Entity::Kind::kFunction, "Test::", "foo",
                       "(int) &&", "snippet.cc", 3, 3, "snippet.cc", 10, 10);
  EXPECT_HAS_ENTITY(index, Entity::Kind::kFunction, "Test::", "foo",
                    "(int) volatile &", "snippet.cc", 4, 6);
  EXPECT_HAS_ENTITY(index, Entity::Kind::kFunction, "Test::", "foo",
                    "(int) const &", "snippet.cc", 7, 7);
  EXPECT_HAS_ENTITY(index, Entity::Kind::kFunction, "", "main", "()",
                    "snippet.cc", 9, 11);
}

TEST(FrontendTest, TemplatedConstructor) {
  auto index = IndexSnippet(
                   "template<typename T>\n"
                   "class Test {\n"
                   " public:\n"
                   "  template<typename U> Test(U&&) {}\n"
                   "};\n"
                   "int main() {\n"
                   "  Test<void>(17);\n"
                   "}\n")
                   ->Export();
  EXPECT_HAS_ENTITY(index, Entity::Kind::kFunction, "Test<T>::", "Test",
                    "<U>(U &&)", "snippet.cc", 4, 4);
  EXPECT_HAS_ENTITY(index, Entity::Kind::kType, "Test<T>::Test<U>(U &&)::", "U",
                    "", "snippet.cc", 4, 4);
  EXPECT_HAS_REFERENCE(
      index, Entity::Kind::kFunction, "Test<void>::", "Test", "<int>(int &&)",
      "snippet.cc", 4, 4, "snippet.cc", 7, 7, /*is_incomplete=*/false,
      /*canonical_entity_id=*/
      RequiredEntityId(index, Entity::Kind::kFunction, "Test<T>::", "Test",
                       "<U>(U &&)", "snippet.cc", 4, 4));
}

TEST(FrontendTest, UnknownPragmas) {
  // This test doesn't actually fail to index, it just tests that unrecognised
  // pragmas are treated as errors by the indexer, and that `IndexSnippet`
  // can detect that there was an error and return nullptr. The indexer itself
  // doesn't care about these errors, so we check that as well.

  // https://chromium.googlesource.com/chromium/src/+/main/tools/clang/plugins/UnsafeBuffersPlugin.cpp
  constexpr auto kSnippet =
      "#pragma allow_unsafe_buffers\n"
      "int foo = 1;\n"
      "#pragma allow_unsafe_libc_calls\n"
      "char bar = 2;\n";

  // First we check that the indexer does indeed treat unrecognised pragmas as
  // errors.
  auto index_one = IndexSnippet(kSnippet,
                                /*extra_args=*/{"-Werror", "-Wunknown-pragmas"},
                                /*fail_on_error=*/true);
  EXPECT_EQ(index_one, nullptr);

  // Then we tell it to ignore those errors, and produce the index regardless.
  auto index_two = IndexSnippet(kSnippet,
                                /*extra_args=*/{"-Werror", "-Wunknown-pragmas"},
                                /*fail_on_error=*/false);
  EXPECT_NE(index_two, nullptr);
  auto flat_index_two = index_two->Export();
  EXPECT_HAS_ENTITY(flat_index_two, Entity::Kind::kVariable, "", "bar", "",
                    "snippet.cc", 4, 4);
  EXPECT_HAS_ENTITY(flat_index_two, Entity::Kind::kVariable, "", "foo", "",
                    "snippet.cc", 2, 2);

  // Now we specifically suppress the unrecognised pragmas, so that we should be
  // able to index without any errors.
  absl::SetFlag(&FLAGS_ignore_pragmas,
                {"allow_unsafe_buffers", "allow_unsafe_libc_calls"});
  auto index_three =
      IndexSnippet(kSnippet,
                   /*extra_args=*/{"-Werror", "-Wunknown-pragmas"},
                   /*fail_on_error=*/true);
  EXPECT_NE(index_three, nullptr);
  auto flat_index_three = index_three->Export();
  EXPECT_HAS_ENTITY(flat_index_three, Entity::Kind::kVariable, "", "bar", "",
                    "snippet.cc", 4, 4);
  EXPECT_HAS_ENTITY(flat_index_three, Entity::Kind::kVariable, "", "foo", "",
                    "snippet.cc", 2, 2);
}

TEST(FrontendTest, TemplatedXRef) {
  auto index = IndexSnippet(
                   "class RefCounted {\n"
                   "public:\n"
                   "  void AddRef() { return; }\n"
                   "};\n"
                   "template <typename T>\n"
                   "class Foo {\n"
                   "public:\n"
                   "  explicit Foo(T* p) : ptr_(p) {\n"
                   "    if (ptr_) {\n"
                   "      ptr_->AddRef();\n"
                   "    }\n"
                   "  }\n"
                   "private:\n"
                   "  T* ptr_;\n"
                   "};\n"
                   "Foo<RefCounted> foo(new RefCounted());\n")
                   ->Export();
  EXPECT_HAS_REFERENCE(index, Entity::Kind::kFunction, "RefCounted::", "AddRef",
                       "()", "snippet.cc", 3, 3, "snippet.cc", 10, 10);
}

TEST(FrontendTest, TemplateMemberFn) {
  auto index = IndexSnippet(
                   "template <typename T>\n"
                   "class TestTemplateClass {\n"
                   " public:\n"
                   "  TestTemplateClass() {}\n"
                   "\n"
                   "  template <typename S>\n"
                   "  static S TestTemplateMemberFn(T t) {\n"
                   "    return static_cast<S>(t);\n"
                   "  }\n"
                   "};\n"
                   "\n"
                   "template <typename T>\n"
                   "class TestTemplateClass2 {\n"
                   " public:\n"
                   "  template<class U> TestTemplateClass2(U&&) { enum E{}; }\n"
                   "};\n"
                   "\n"
                   "void template_xrefs() {\n"
                   "  int template_xref =\n"
                   "      TestTemplateClass<int>::"
                   "TestTemplateMemberFn<unsigned int>(99);\n"
                   "  TestTemplateClass2<char> test2(3);\n"
                   "}\n"
                   "\n"
                   "template <typename T>\n"
                   "class TestTemplateClass3 : public TestTemplateClass<T> {\n"
                   "};\n"
                   "void more_template_xrefs() {\n"
                   "  int template_xref =\n"
                   "      TestTemplateClass3<char>::"
                   "TestTemplateMemberFn<long>(99);\n"
                   "}\n")
                   ->Export();
  EXPECT_HAS_ENTITY(index, Entity::Kind::kClass, "", "TestTemplateClass", "<T>",
                    "snippet.cc", 1, 10, /*is_incomplete=*/false);
  EXPECT_HAS_ENTITY(
      index, Entity::Kind::kClass, "", "TestTemplateClass", "<int>",
      "snippet.cc", 1, 10, /*is_incomplete=*/false, /*canonical_entity_id=*/
      RequiredEntityId(index, Entity::Kind::kClass, "", "TestTemplateClass",
                       "<T>", "snippet.cc", 1, 10));
  EXPECT_HAS_REFERENCE(
      index, Entity::Kind::kClass, "", "TestTemplateClass", "<int>",
      "snippet.cc", 1, 10, "snippet.cc", 20, 20, /*is_incomplete=*/false,
      /*canonical_entity_id=*/
      RequiredEntityId(index, Entity::Kind::kClass, "", "TestTemplateClass",
                       "<T>", "snippet.cc", 1, 10));
  EXPECT_HAS_ENTITY(index, Entity::Kind::kClass, "", "TestTemplateClass2",
                    "<T>", "snippet.cc", 12, 16, /*is_incomplete=*/false);
  EXPECT_HAS_REFERENCE(index, Entity::Kind::kClass, "", "TestTemplateClass2",
                       "<T>", "snippet.cc", 12, 16, "snippet.cc", 21, 21,
                       /*is_incomplete=*/false);
  EXPECT_HAS_ENTITY(
      index, Entity::Kind::kClass, "", "TestTemplateClass2", "<char>",
      "snippet.cc", 12, 16, /*is_incomplete=*/false, /*canonical_entity_id=*/
      RequiredEntityId(index, Entity::Kind::kClass, "", "TestTemplateClass2",
                       "<T>", "snippet.cc", 12, 16));
  EXPECT_HAS_REFERENCE(
      index, Entity::Kind::kClass, "", "TestTemplateClass2", "<char>",
      "snippet.cc", 12, 16, "snippet.cc", 21, 21, /*is_incomplete=*/false,
      /*canonical_entity_id=*/
      RequiredEntityId(index, Entity::Kind::kClass, "", "TestTemplateClass2",
                       "<T>", "snippet.cc", 12, 16));
  EXPECT_HAS_ENTITY(index, Entity::Kind::kVariable, "", "t", "", "snippet.cc",
                    7, 7, /*is_incomplete=*/false);
  EXPECT_HAS_REFERENCE(index, Entity::Kind::kVariable, "", "t", "",
                       "snippet.cc", 7, 7, "snippet.cc", 8, 8,
                       /*is_incomplete=*/false);
  EXPECT_HAS_ENTITY(index, Entity::Kind::kVariable, "", "t", "", "snippet.cc",
                    7, 7, /*is_incomplete=*/false, /*canonical_entity_id=*/
                    RequiredEntityId(index, Entity::Kind::kVariable, "", "t",
                                     "", "snippet.cc", 7, 7));
  EXPECT_HAS_REFERENCE(index, Entity::Kind::kVariable, "", "t", "",
                       "snippet.cc", 7, 7, "snippet.cc", 8, 8,
                       /*is_incomplete=*/false, /*canonical_entity_id=*/
                       RequiredEntityId(index, Entity::Kind::kVariable, "", "t",
                                        "", "snippet.cc", 7, 7));
  EXPECT_HAS_ENTITY(index, Entity::Kind::kVariable, "", "template_xref", "",
                    "snippet.cc", 19, 20, /*is_incomplete=*/false);
  EXPECT_HAS_ENTITY(index, Entity::Kind::kFunction, "", "template_xrefs", "()",
                    "snippet.cc", 18, 22, /*is_incomplete=*/false);
  EXPECT_HAS_ENTITY(index, Entity::Kind::kVariable, "", "test2", "",
                    "snippet.cc", 21, 21, /*is_incomplete=*/false);
  EXPECT_HAS_ENTITY(index, Entity::Kind::kType, "TestTemplateClass2<T>::", "T",
                    "", "snippet.cc", 12, 12, /*is_incomplete=*/false);
  EXPECT_HAS_ENTITY(index, Entity::Kind::kFunction,
                    "TestTemplateClass2<T>::", "TestTemplateClass2",
                    "<U>(U &&)", "snippet.cc", 15, 15, /*is_incomplete=*/false);
  EXPECT_HAS_ENTITY(index, Entity::Kind::kEnum,
                    "TestTemplateClass2<T>::TestTemplateClass2<U>(U &&)::", "E",
                    "", "snippet.cc", 15, 15, /*is_incomplete=*/false);
  EXPECT_HAS_ENTITY(index, Entity::Kind::kType,
                    "TestTemplateClass2<T>::TestTemplateClass2<U>(U &&)::", "U",
                    "", "snippet.cc", 15, 15, /*is_incomplete=*/false);
  EXPECT_HAS_ENTITY(
      index, Entity::Kind::kFunction,
      "TestTemplateClass2<char>::", "TestTemplateClass2", "<int>(int &&)",
      "snippet.cc", 15, 15, /*is_incomplete=*/false, /*canonical_entity_id=*/
      RequiredEntityId(index, Entity::Kind::kFunction,
                       "TestTemplateClass2<T>::", "TestTemplateClass2",
                       "<U>(U &&)", "snippet.cc", 15, 15));
  EXPECT_HAS_ENTITY(
      index, Entity::Kind::kEnum,
      "TestTemplateClass2<char>::TestTemplateClass2<int>(int &&)::", "E", "",
      "snippet.cc", 15, 15, /*is_incomplete=*/false, /*canonical_entity_id=*/
      RequiredEntityId(index, Entity::Kind::kEnum,
                       "TestTemplateClass2<T>::TestTemplateClass2<U>(U &&)::",
                       "E", "", "snippet.cc", 15, 15));
  EXPECT_HAS_ENTITY(index, Entity::Kind::kType, "TestTemplateClass<T>::", "T",
                    "", "snippet.cc", 1, 1, /*is_incomplete=*/false);
  EXPECT_HAS_REFERENCE(index, Entity::Kind::kType,
                       "TestTemplateClass<T>::", "T", "", "snippet.cc", 1, 1,
                       "snippet.cc", 7, 7, /*is_incomplete=*/false);
  EXPECT_HAS_ENTITY(index, Entity::Kind::kFunction,
                    "TestTemplateClass<T>::", "TestTemplateClass", "()",
                    "snippet.cc", 4, 4, /*is_incomplete=*/false);
  EXPECT_HAS_ENTITY(index, Entity::Kind::kFunction,
                    "TestTemplateClass<T>::", "TestTemplateMemberFn", "<S>(T)",
                    "snippet.cc", 6, 9, /*is_incomplete=*/false);
  EXPECT_HAS_ENTITY(index, Entity::Kind::kType,
                    "TestTemplateClass<T>::TestTemplateMemberFn<S>(T)::", "S",
                    "", "snippet.cc", 6, 6, /*is_incomplete=*/false);
  EXPECT_HAS_REFERENCE(
      index, Entity::Kind::kType,
      "TestTemplateClass<T>::TestTemplateMemberFn<S>(T)::", "S", "",
      "snippet.cc", 6, 6, "snippet.cc", 7, 7, /*is_incomplete=*/false);
  EXPECT_HAS_ENTITY(
      index, Entity::Kind::kFunction,
      "TestTemplateClass<int>::", "TestTemplateMemberFn", "<unsigned int>(int)",
      "snippet.cc", 6, 9, /*is_incomplete=*/false, /*canonical_entity_id=*/
      RequiredEntityId(index, Entity::Kind::kFunction, "TestTemplateClass<T>::",
                       "TestTemplateMemberFn", "<S>(T)", "snippet.cc", 6, 9));
  EXPECT_HAS_REFERENCE(
      index, Entity::Kind::kFunction,
      "TestTemplateClass<int>::", "TestTemplateMemberFn", "<unsigned int>(int)",
      "snippet.cc", 6, 9, "snippet.cc", 20, 20, /*is_incomplete=*/false,
      /*canonical_entity_id=*/
      RequiredEntityId(index, Entity::Kind::kFunction, "TestTemplateClass<T>::",
                       "TestTemplateMemberFn", "<S>(T)", "snippet.cc", 6, 9));
  // Implicit entities for entities which have canonical ones.
  EXPECT_HAS_ENTITY(
      index, Entity::Kind::kFunction,
      "TestTemplateClass3<char>::", "TestTemplateClass3", "()", "snippet.cc",
      25, 25, /*is_incomplete=*/false, /*canonical_entity_id=*/std::nullopt,
      /*implicitly_defined_for_entity_id=*/
      RequiredEntityId(
          index, Entity::Kind::kClass, "", "TestTemplateClass3", "<char>",
          "snippet.cc", 24, 26, /*is_incomplete=*/false,
          /*canonical_entity_id=*/
          RequiredEntityId(index, Entity::Kind::kClass, "",
                           "TestTemplateClass3", "<T>", "snippet.cc", 24, 26)));
  EXPECT_HAS_ENTITY(
      index, Entity::Kind::kFunction,
      "TestTemplateClass3<char>::", "TestTemplateClass3",
      "(TestTemplateClass3<char> &&)", "snippet.cc", 25, 25,
      /*is_incomplete=*/false, /*canonical_entity_id=*/std::nullopt,
      /*implicitly_defined_for_entity_id=*/
      RequiredEntityId(
          index, Entity::Kind::kClass, "", "TestTemplateClass3", "<char>",
          "snippet.cc", 24, 26, /*is_incomplete=*/false,
          /*canonical_entity_id=*/
          RequiredEntityId(index, Entity::Kind::kClass, "",
                           "TestTemplateClass3", "<T>", "snippet.cc", 24, 26)));
  EXPECT_HAS_ENTITY(
      index, Entity::Kind::kFunction,
      "TestTemplateClass3<char>::", "TestTemplateClass3",
      "(const TestTemplateClass3<char> &)", "snippet.cc", 25, 25,
      /*is_incomplete=*/false, /*canonical_entity_id=*/std::nullopt,
      /*implicitly_defined_for_entity_id=*/
      RequiredEntityId(
          index, Entity::Kind::kClass, "", "TestTemplateClass3", "<char>",
          "snippet.cc", 24, 26, /*is_incomplete=*/false,
          /*canonical_entity_id=*/
          RequiredEntityId(index, Entity::Kind::kClass, "",
                           "TestTemplateClass3", "<T>", "snippet.cc", 24, 26)));
  EXPECT_HAS_ENTITY(
      index, Entity::Kind::kFunction, "TestTemplateClass3<char>::", "operator=",
      "(TestTemplateClass3<char> &&)", "snippet.cc", 25, 25,
      /*is_incomplete=*/false, /*canonical_entity_id=*/std::nullopt,
      /*implicitly_defined_for_entity_id=*/
      RequiredEntityId(
          index, Entity::Kind::kClass, "", "TestTemplateClass3", "<char>",
          "snippet.cc", 24, 26, /*is_incomplete=*/false,
          /*canonical_entity_id=*/
          RequiredEntityId(index, Entity::Kind::kClass, "",
                           "TestTemplateClass3", "<T>", "snippet.cc", 24, 26)));
  EXPECT_HAS_ENTITY(
      index, Entity::Kind::kFunction, "TestTemplateClass3<char>::", "operator=",
      "(const TestTemplateClass3<char> &)", "snippet.cc", 25, 25,
      /*is_incomplete=*/false, /*canonical_entity_id=*/std::nullopt,
      /*implicitly_defined_for_entity_id=*/
      RequiredEntityId(
          index, Entity::Kind::kClass, "", "TestTemplateClass3", "<char>",
          "snippet.cc", 24, 26, /*is_incomplete=*/false,
          /*canonical_entity_id=*/
          RequiredEntityId(index, Entity::Kind::kClass, "",
                           "TestTemplateClass3", "<T>", "snippet.cc", 24, 26)));
  // Implicitly defined destructor in a class instantiated from a template.
  EXPECT_HAS_ENTITY(
      index, Entity::Kind::kFunction,
      "TestTemplateClass3<char>::", "~TestTemplateClass3", "()", "snippet.cc",
      25, 25, /*is_incomplete=*/false, /*canonical_entity_id=*/std::nullopt,
      /*implicitly_defined_for_entity_id=*/
      RequiredEntityId(
          index, Entity::Kind::kClass, "", "TestTemplateClass3", "<char>",
          "snippet.cc", 24, 26, /*is_incomplete=*/false,
          /*canonical_entity_id=*/
          RequiredEntityId(index, Entity::Kind::kClass, "",
                           "TestTemplateClass3", "<T>", "snippet.cc", 24, 26)));
}

TEST(FrontendTest, ImplicitCode) {
  auto index = IndexSnippet(
                   "class Foo {\n"
                   " public:\n"
                   "  virtual ~Foo() {}\n"
                   "};\n"
                   "Foo instance;"
                   "class Bar : public Foo {};\n"
                   "Bar instance2;\n"
                   "Bar func() { return {}; }\n"
                   "typedef union { int x; short y; } u;\n"
                   "struct Baz {\n"
                   "  Baz() {\n"
                   "    int arr[] = {1, 2, 3};\n"
                   "    for (auto x : arr) {};\n"
                   "  };\n"
                   "  union { int a; char b; };  // anonymous union field\n"
                   "};")
                   ->Export();

  EXPECT_HAS_ENTITY(index, Entity::Kind::kFunction, "Foo::", "~Foo", "()",
                    "snippet.cc", 3, 3);
  EXPECT_HAS_ENTITY(index, Entity::Kind::kFunction, "Foo::", "Foo", "()",
                    "snippet.cc", 1, 1, /*is_incomplete=*/false,
                    /*canonical_entity_id=*/std::nullopt,
                    /*implicitly_defined_for_entity_id=*/
                    RequiredEntityId(index, Entity::Kind::kClass, "", "Foo", "",
                                     "snippet.cc", 1, 4));
  EXPECT_HAS_ENTITY(index, Entity::Kind::kFunction, "Foo::", "Foo",
                    "(const Foo &)", "snippet.cc", 1, 1,
                    /*is_incomplete=*/false,
                    /*canonical_entity_id=*/
                    std::nullopt, /*implicitly_defined_for_entity_id=*/
                    RequiredEntityId(index, Entity::Kind::kClass, "", "Foo", "",
                                     "snippet.cc", 1, 4));
  EXPECT_HAS_ENTITY(index, Entity::Kind::kFunction,
                    "Foo::", "operator=", "(const Foo &)", "snippet.cc", 1, 1,
                    /*is_incomplete=*/false,
                    /*canonical_entity_id=*/
                    std::nullopt, /*implicitly_defined_for_entity_id=*/
                    RequiredEntityId(index, Entity::Kind::kClass, "", "Foo", "",
                                     "snippet.cc", 1, 4));
  EXPECT_HAS_ENTITY(index, Entity::Kind::kFunction, "Bar::", "Bar", "()",
                    "snippet.cc", 5, 5, /*is_incomplete=*/false,
                    /*canonical_entity_id=*/std::nullopt,
                    /*implicitly_defined_for_entity_id=*/
                    RequiredEntityId(index, Entity::Kind::kClass, "", "Bar", "",
                                     "snippet.cc", 5, 5));
  EXPECT_HAS_ENTITY(index, Entity::Kind::kFunction, "Bar::", "~Bar", "()",
                    "snippet.cc", 5, 5, /*is_incomplete=*/false,
                    /*canonical_entity_id=*/std::nullopt,
                    /*implicitly_defined_for_entity_id=*/
                    RequiredEntityId(index, Entity::Kind::kClass, "", "Bar", "",
                                     "snippet.cc", 5, 5));
  EXPECT_HAS_REFERENCE(index, Entity::Kind::kFunction, "Foo::", "Foo", "()",
                       "snippet.cc", 1, 1, "snippet.cc", 5, 5,
                       /*is_incomplete=*/false,
                       /*canonical_entity_id=*/std::nullopt,
                       /*implicitly_defined_for_entity_id=*/
                       RequiredEntityId(index, Entity::Kind::kClass, "", "Foo",
                                        "", "snippet.cc", 1, 4));
  EXPECT_HAS_REFERENCE(index, Entity::Kind::kFunction, "Bar::", "Bar", "()",
                       "snippet.cc", 5, 5, "snippet.cc", 7, 7,
                       /*is_incomplete=*/false,
                       /*canonical_entity_id=*/
                       std::nullopt, /*implicitly_defined_for_entity_id=*/
                       RequiredEntityId(index, Entity::Kind::kClass, "", "Bar",
                                        "", "snippet.cc", 5, 5));
  EXPECT_HAS_ENTITY(index, Entity::Kind::kFunction, "Baz::", "Baz", "()",
                    "snippet.cc", 10, 13);
  EXPECT_HAS_ENTITY(index, Entity::Kind::kFunction, "Baz::", "Baz", "(Baz &&)",
                    "snippet.cc", 9, 9, /*is_incomplete=*/false,
                    /*canonical_entity_id=*/std::nullopt,
                    /*implicitly_defined_for_entity_id=*/
                    RequiredEntityId(index, Entity::Kind::kClass, "", "Baz", "",
                                     "snippet.cc", 9, 15));
  EXPECT_HAS_ENTITY(index, Entity::Kind::kFunction, "Baz::", "Baz",
                    "(const Baz &)", "snippet.cc", 9, 9,
                    /*is_incomplete=*/false,
                    /*canonical_entity_id=*/
                    std::nullopt, /*implicitly_defined_for_entity_id=*/
                    RequiredEntityId(index, Entity::Kind::kClass, "", "Baz", "",
                                     "snippet.cc", 9, 15));
  EXPECT_HAS_ENTITY(index, Entity::Kind::kFunction,
                    "Baz::", "operator=", "(Baz &&)", "snippet.cc", 9, 9,
                    /*is_incomplete=*/false,
                    /*canonical_entity_id=*/
                    std::nullopt, /*implicitly_defined_for_entity_id=*/
                    RequiredEntityId(index, Entity::Kind::kClass, "", "Baz", "",
                                     "snippet.cc", 9, 15));
  EXPECT_HAS_ENTITY(index, Entity::Kind::kFunction,
                    "Baz::", "operator=", "(const Baz &)", "snippet.cc", 9, 9,
                    /*is_incomplete=*/false,
                    /*canonical_entity_id=*/
                    std::nullopt, /*implicitly_defined_for_entity_id=*/
                    RequiredEntityId(index, Entity::Kind::kClass, "", "Baz", "",
                                     "snippet.cc", 9, 15));
  EXPECT_HAS_ENTITY(index, Entity::Kind::kFunction, "Baz::", "~Baz", "()",
                    "snippet.cc", 9, 9, /*is_incomplete=*/false,
                    /*canonical_entity_id=*/std::nullopt,
                    /*implicitly_defined_for_entity_id=*/
                    RequiredEntityId(index, Entity::Kind::kClass, "", "Baz", "",
                                     "snippet.cc", 9, 15));

  // Anonymous union destructor should be absent, with or without implicit-for.
  EXPECT_FALSE(IndexHasEntity(
      index, Entity::Kind::kFunction, "(anonymous union)::", "~u", "()",
      "snippet.cc", 8, 8, /*is_incomplete=*/false,
      /*canonical_entity_id=*/
      std::nullopt, /*implicitly_defined_for_entity_id=*/
      RequiredEntityId(index, Entity::Kind::kClass, "", "(anonymous union)", "",
                       "snippet.cc", 8, 8)));
  EXPECT_FALSE(IndexHasEntity(index, Entity::Kind::kFunction,
                              "(anonymous union)::", "~u", "()", "snippet.cc",
                              8, 8));
  // Implicit variables from range for loops should be absent.
  EXPECT_FALSE(IndexHasEntity(index, Entity::Kind::kVariable, "", "__begin1",
                              "", "snippet.cc", 12, 12));
  EXPECT_FALSE(IndexHasEntity(index, Entity::Kind::kVariable, "", "__end1", "",
                              "snippet.cc", 12, 12));
  EXPECT_FALSE(IndexHasEntity(index, Entity::Kind::kVariable, "", "__range1",
                              "", "snippet.cc", 12, 12));
  EXPECT_FALSE(IndexHasReference(index, Entity::Kind::kVariable, "", "__range1",
                                 "", "snippet.cc", 12, 12, "snippet.cc", 12,
                                 12));
  // Implicit unnamed field produced by an anonymous union should be absent.
  EXPECT_FALSE(IndexHasEntity(index, Entity::Kind::kVariable, "Baz::",
                              "(anonymous union)", "", "snippet.cc", 14, 14));
  // Unreferenced `operator delete` should be absent.
  EXPECT_FALSE(IndexHasEntity(index, Entity::Kind::kFunction, "",
                              "operator delete", "(void *)", "", 0, 0,
                              /*is_incomplete=*/true));
}

TEST(FrontendTest, ReferencedImplicitCode) {
  auto index = IndexSnippet("void func() { delete new int; }\n")->Export();
  EXPECT_HAS_ENTITY(index, Entity::Kind::kFunction, "", "func", "()",
                    "snippet.cc", 1, 1);
  EXPECT_HAS_ENTITY(index, Entity::Kind::kFunction, "", "operator delete",
                    "(void *, unsigned long)", "", 0, 0,
                    /*is_incomplete=*/true);
  EXPECT_HAS_REFERENCE(index, Entity::Kind::kFunction, "", "operator delete",
                       "(void *, unsigned long)", "", 0, 0, "snippet.cc", 1, 1,
                       /*is_incomplete=*/true);
  EXPECT_HAS_ENTITY(index, Entity::Kind::kFunction, "", "operator new",
                    "(unsigned long)", "", 0, 0, /*is_incomplete=*/true);
  EXPECT_HAS_REFERENCE(index, Entity::Kind::kFunction, "", "operator new",
                       "(unsigned long)", "", 0, 0, "snippet.cc", 1, 1,
                       /*is_incomplete=*/true);
}

TEST(FrontendTest, ImplicitComparisonInstantiation) {
  auto index = IndexSnippet(
                   "namespace std {\n"
                   "struct strong_ordering {\n"
                   "  int n;\n"
                   "  static const strong_ordering less, equal, greater;\n"
                   "};\n"
                   "constexpr strong_ordering strong_ordering::less = {-1};\n"
                   "constexpr strong_ordering strong_ordering::equal = {0};\n"
                   "constexpr strong_ordering strong_ordering::greater = {1};\n"
                   "constexpr bool operator!=(strong_ordering, int);\n"
                   "} // namespace std\n"
                   "template <typename T>\n"
                   "struct TestTemplateClass {\n"
                   "  constexpr auto operator<=>(const TestTemplateClass<T>&) "
                   "const = default;\n"
                   "};\n"
                   "const bool X = (TestTemplateClass<int>() ==\n"
                   "                TestTemplateClass<int>());\n",
                   {"-std=c++20"})
                   ->Export();
  // Implicit `operator==` instantiated from a template implicit `operator==`
  // coming from `auto operator<=>`.
  EXPECT_HAS_ENTITY(
      index, Entity::Kind::kFunction, "TestTemplateClass<int>::", "operator==",
      "(const TestTemplateClass<int> &) const", "snippet.cc", 13, 13,
      /*is_incomplete=*/false, /*canonical_entity_id=*/
      RequiredEntityId(
          index, Entity::Kind::kFunction, "TestTemplateClass<T>::",
          "operator==", "(const TestTemplateClass<T> &) const", "snippet.cc",
          13, 13, /*is_incomplete=*/false, /*canonical_entity_id=*/std::nullopt,
          /*implicitly_defined_for_entity_id=*/
          RequiredEntityId(index, Entity::Kind::kClass, "", "TestTemplateClass",
                           "<T>", "snippet.cc", 11, 14)));
  EXPECT_HAS_REFERENCE(
      index, Entity::Kind::kFunction, "TestTemplateClass<int>::", "operator==",
      "(const TestTemplateClass<int> &) const", "snippet.cc", 13, 13,
      "snippet.cc", 15, 16, /*is_incomplete=*/false, /*canonical_entity_id=*/
      RequiredEntityId(
          index, Entity::Kind::kFunction, "TestTemplateClass<T>::",
          "operator==", "(const TestTemplateClass<T> &) const", "snippet.cc",
          13, 13, /*is_incomplete=*/false, /*canonical_entity_id=*/std::nullopt,
          /*implicitly_defined_for_entity_id=*/
          RequiredEntityId(index, Entity::Kind::kClass, "", "TestTemplateClass",
                           "<T>", "snippet.cc", 11, 14)));
}

TEST(FrontendTest, CommandLineMacro) {
  auto index = IndexSnippet("int MACRO;", {"-DMACRO=expansion"})->Export();
  EXPECT_HAS_ENTITY(index, Entity::Kind::kVariable, "", "expansion", "",
                    "snippet.cc", 1, 1);
  int found = 0;
  for (const auto& index_entity : index.entities) {
    if (index_entity.full_name() == "MACRO") {
      EXPECT_EQ(index_entity.kind(), Entity::Kind::kMacro);
      // NOTE(kartynnik): Why isn't this `<command line>`?
      EXPECT_EQ(index.locations[index_entity.location_id()].path(),
                "<built-in>");
      ++found;
    }
  }
  EXPECT_EQ(found, 1);
}
}  // namespace indexer
}  // namespace oss_fuzz
