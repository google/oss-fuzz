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

#include "indexer/index/file_copier.h"

#include <filesystem>  // NOLINT
#include <fstream>
#include <optional>
#include <sstream>
#include <string>

#include "gtest/gtest.h"

namespace oss_fuzz {
namespace indexer {
namespace {
void CreateFile(const std::filesystem::path& path) {
  std::filesystem::create_directories(path.parent_path());
  std::ofstream tmp_file(path);
  tmp_file << path.filename().string();
  ASSERT_TRUE(tmp_file.good());
}

std::optional<std::string> GetFileContents(const std::filesystem::path& path) {
  std::ifstream file(path);
  if (!file.good()) {
    return std::nullopt;
  }
  std::stringstream buffer;
  buffer << file.rdbuf();
  return buffer.str();
}
}  // namespace

TEST(FileCopierTest, AbsoluteToIndexPath) {
  auto tmp_dir_path = std::filesystem::path(::testing::TempDir());
  auto base_path = tmp_dir_path / "src";
  auto index_path = tmp_dir_path / "idx";
  FileCopier file_copier(base_path.string(), index_path.string(), {"/"});

  EXPECT_EQ(file_copier.AbsoluteToIndexPath("/a/b/c/d.cc"), "/a/b/c/d.cc");
  EXPECT_EQ(
      file_copier.AbsoluteToIndexPath((base_path / "a/b/c/d.cc").string()),
      "a/b/c/d.cc");
  EXPECT_DEATH(file_copier.AbsoluteToIndexPath("a/b/c/d.cc"),
               "Absolute path expected");
}

TEST(FileCopierTest, AbsoluteToIndexPathOutside) {
  auto tmp_dir_path = std::filesystem::path(::testing::TempDir());
  auto base_path = tmp_dir_path / "src";
  auto index_path = tmp_dir_path / "idx";
  FileCopier file_copier(base_path.string(), index_path.string(), {"/sysroot"});

  EXPECT_DEATH(file_copier.AbsoluteToIndexPath("/a/b/c/d.cc"), "/a/b/c/d.cc");
}

TEST(FileCopierTest, FileCopying) {
  auto tmp_dir_path = std::filesystem::path(::testing::TempDir());
  auto base_path = tmp_dir_path / "src";
  auto index_path = tmp_dir_path / "idx";
  auto sysroot_path = tmp_dir_path / "sysroot";
  FileCopier file_copier(base_path.string(), index_path.string(),
                         {sysroot_path.string()});

  auto file_a = base_path / "a.cc";
  CreateFile(file_a);
  auto file_a_copy = index_path / "relative/a.cc";

  auto file_b = base_path / "x" / "b.cc";
  CreateFile(file_b);
  auto file_b_copy = index_path / "relative/x/b.cc";

  auto file_c = sysroot_path / "y/z/c.cc";
  CreateFile(file_c);
  auto file_c_copy = index_path / "absolute" /
                     sysroot_path.lexically_relative("/") / "y/z/c.cc";

  file_copier.RegisterIndexedFile(
      file_copier.AbsoluteToIndexPath(file_a.string()));
  file_copier.RegisterIndexedFile(
      file_copier.AbsoluteToIndexPath(file_b.string()));
  file_copier.RegisterIndexedFile(
      file_copier.AbsoluteToIndexPath(file_c.string()));

  file_copier.CopyIndexedFiles();

  EXPECT_EQ(GetFileContents(file_a_copy).value_or(""), "a.cc");
  EXPECT_EQ(GetFileContents(file_b_copy).value_or(""), "b.cc");
  EXPECT_EQ(GetFileContents(file_c_copy).value_or(""), "c.cc");
}

}  // namespace indexer
}  // namespace oss_fuzz
