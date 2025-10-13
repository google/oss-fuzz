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

#include <cstddef>
#include <filesystem>  // NOLINT
#include <string>

#include "indexer/index/types.h"
#include "absl/cleanup/cleanup.h"
#include "absl/log/log.h"
#include "absl/types/span.h"
#include "sqlite3.h"

#define SCHEMA_VERSION "4"

namespace oss_fuzz {
namespace indexer {
namespace {

// We disable foreign keys and don't enforce unique constraints by default
// to speed up index writing (and to account for forward references without
// transactions). However, with `enable_expensive_checks`, we add these
// afterwards.

const char kCreateDb[] =
    "PRAGMA foreign_keys = OFF;\n"
    "PRAGMA user_version = " SCHEMA_VERSION
    ";\n"
    "\n"
    "CREATE TABLE location(\n"
    "  id             INTEGER PRIMARY KEY,\n"
    "  dirname        TEXT NOT NULL,\n"
    "  basename       TEXT NOT NULL,\n"
    "  start_line     INT NOT NULL,\n"
    "  end_line       INT NOT NULL);\n"
    "\n"
    "CREATE TABLE entity(\n"
    "  id                            INTEGER PRIMARY KEY,\n"
    "  kind                          INT NOT NULL,\n"
    "  is_incomplete                 BOOLEAN,\n"
    "  name_prefix                   TEXT,\n"
    "  name                          TEXT NOT NULL,\n"
    "  name_suffix                   TEXT,\n"
    "  location_id                   INTEGER NOT NULL,\n"
    "  substitute_entity_id          INTEGER,\n"
    "  substitute_relationship_kind  INTEGER,\n"
    "  enum_value                    TEXT,\n"
    "  virtual_method_kind           INT NOT NULL,\n"
    "  FOREIGN KEY (location_id) REFERENCES location(id),\n"
    "  FOREIGN KEY (substitute_entity_id) REFERENCES entity(id),\n"
    "  CHECK("
    "  (substitute_entity_id IS NULL) == (substitute_relationship_kind IS NULL)"
    "  ));\n"
    "\n"
    "CREATE TABLE reference(\n"
    "  id             INTEGER PRIMARY KEY,\n"
    "  entity_id      INTEGER NOT NULL,\n"
    "  location_id    INTEGER NOT NULL,\n"
    "  FOREIGN KEY (entity_id) REFERENCES entity(id),\n"
    "  FOREIGN KEY (location_id) REFERENCES location(id));\n"
    "\n"
    "CREATE TABLE virtual_method_link(\n"
    "  id                INTEGER PRIMARY KEY,\n"
    "  parent_entity_id  INTEGER NOT NULL,\n"
    "  child_entity_id   INTEGER NOT NULL,\n"
    "  FOREIGN KEY (parent_entity_id) REFERENCES entity(id),\n"
    "  FOREIGN KEY (child_entity_id) REFERENCES entity(id));\n"
    "\n"
    "CREATE INDEX entity_name ON entity(name);\n"
    "\n"
    "CREATE INDEX location_basename_start_line ON location("
    "  basename,\n"
    "  start_line);\n"
    "\n"
    "CREATE INDEX reference_entity_location ON reference("
    "  entity_id,\n"
    "  location_id);\n"
    "\n"
    "CREATE INDEX virtual_method_link_parent ON virtual_method_link("
    "  parent_entity_id);";

// UNIQUE indices are almost equivalent to UNIQUE column constraints (only used
// with `enable_expensive_checks`).
const char kCreateUniqueIndices[] =
    "CREATE UNIQUE INDEX unique_location\n"
    "  ON location(dirname, basename, start_line, end_line);\n"
    "\n"
    "CREATE UNIQUE INDEX unique_entity\n"
    "  ON entity(kind, name_prefix, name, name_suffix, location_id);\n"
    "\n"
    "CREATE UNIQUE INDEX unique_reference\n"
    "  ON reference(entity_id, location_id);\n"
    "\n"
    "CREATE UNIQUE INDEX unique_link\n"
    "  ON virtual_method_link(parent_entity_id, child_entity_id);";

const char kInsertLocation[] =
    "INSERT INTO location\n"
    "  (id, dirname, basename, start_line, end_line)\n"
    "  VALUES (?1, ?2, ?3, ?4, ?5);";

const char kInsertEntity[] =
    "INSERT INTO entity\n"
    "  (id, kind, is_incomplete, name_prefix, name, name_suffix, location_id,\n"
    "   substitute_entity_id, substitute_relationship_kind, enum_value,\n"
    "   virtual_method_kind)\n"
    "  VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11);";

const char kInsertReference[] =
    "INSERT INTO reference\n"
    "  (id, entity_id, location_id)\n"
    "  VALUES (?1, ?2, ?3);";

const char kInsertLink[] =
    "INSERT INTO virtual_method_link\n"
    "  (id, parent_entity_id, child_entity_id)\n"
    "  VALUES (?1, ?2, ?3);";

const char kFinalizeDb[] =
    "VACUUM;\n"
    "REINDEX;\n"
    "ANALYZE;\n";

bool InsertLocations(sqlite3* db, absl::Span<const Location> locations) {
  sqlite3_stmt* insert_location = nullptr;
  if (sqlite3_prepare_v2(db, kInsertLocation, sizeof(kInsertLocation),
                         &insert_location, nullptr) != SQLITE_OK) {
    LOG(ERROR) << "sqlite compiling prepared statement failed: `"
               << sqlite3_errmsg(db) << "`";
    return false;
  }
  absl::Cleanup cleanup = [insert_location] {
    sqlite3_finalize(insert_location);
  };

  for (LocationId i = 0; i < locations.size(); ++i) {
    const Location& location = locations[i];
    std::filesystem::path location_path(location.path());
    const std::string dirname = location_path.parent_path();
    const std::string basename = location_path.filename();

    if (sqlite3_bind_int64(insert_location, 1, i) != SQLITE_OK ||
        sqlite3_bind_text(insert_location, 2, dirname.data(), dirname.size(),
                          SQLITE_STATIC) != SQLITE_OK ||
        sqlite3_bind_text(insert_location, 3, basename.data(), basename.size(),
                          SQLITE_STATIC) != SQLITE_OK ||

        sqlite3_bind_int(insert_location, 4, location.start_line()) !=
            SQLITE_OK ||

        sqlite3_bind_int(insert_location, 5, location.end_line()) !=
            SQLITE_OK) {
      LOG(ERROR) << "sqlite binding insert_location failed: `"
                 << sqlite3_errmsg(db) << "`";
      return false;
    }

    if (sqlite3_step(insert_location) != SQLITE_DONE) {
      LOG(ERROR) << "sqlite executing insert_entity failed: `"
                 << sqlite3_errmsg(db) << "`";
      return false;
    }

    sqlite3_reset(insert_location);
    sqlite3_clear_bindings(insert_location);
  }

  return true;
}

bool InsertEntities(sqlite3* db, absl::Span<const Entity> entities) {
  sqlite3_stmt* insert_entity = nullptr;
  if (sqlite3_prepare_v2(db, kInsertEntity, sizeof(kInsertEntity),
                         &insert_entity, nullptr) != SQLITE_OK) {
    LOG(ERROR) << "sqlite compiling prepared statement failed: `"
               << sqlite3_errmsg(db) << "`";
    return false;
  }
  absl::Cleanup cleanup = [insert_entity] { sqlite3_finalize(insert_entity); };

  for (EntityId i = 0; i < entities.size(); ++i) {
    const Entity& entity = entities[i];
    if (sqlite3_bind_int64(insert_entity, 1, i) != SQLITE_OK ||
        sqlite3_bind_int(insert_entity, 2, static_cast<int>(entity.kind())) !=
            SQLITE_OK ||
        sqlite3_bind_int(insert_entity, 3,
                         static_cast<int>(entity.is_incomplete())) !=
            SQLITE_OK ||
        sqlite3_bind_text(insert_entity, 5, entity.name().data(),
                          entity.name().size(), SQLITE_STATIC) != SQLITE_OK ||

        sqlite3_bind_int64(insert_entity, 7, entity.location_id()) !=
            SQLITE_OK) {
      LOG(ERROR) << "sqlite binding insert_entity failed: `"
                 << sqlite3_errmsg(db) << "`";
      return false;
    }

    // Note that unbound parameters default to NULL, which is allowed in our
    // schema for name_{prefix,suffix}, substitute_entity_{id,relationship}, and
    // enum_value.

    if (!entity.name_prefix().empty() &&
        sqlite3_bind_text(insert_entity, 4, entity.name_prefix().data(),
                          entity.name_prefix().size(),
                          SQLITE_STATIC) != SQLITE_OK) {
      return false;
    }

    if (!entity.name_suffix().empty() &&
        sqlite3_bind_text(insert_entity, 6, entity.name_suffix().data(),
                          entity.name_suffix().size(),
                          SQLITE_STATIC) != SQLITE_OK) {
      return false;
    }

    if (entity.substitute_relationship().has_value()) {
      if (sqlite3_bind_int64(
              insert_entity, 8,
              entity.substitute_relationship()->substitute_entity_id()) !=
          SQLITE_OK) {
        return false;
      }

      if (sqlite3_bind_int64(
              insert_entity, 9,
              static_cast<int>(entity.substitute_relationship()->kind())) !=
          SQLITE_OK) {
        return false;
      }
    }

    if (entity.enum_value().has_value() &&
        sqlite3_bind_text(insert_entity, 10, entity.enum_value()->data(),
                          entity.enum_value()->size(),
                          SQLITE_STATIC) != SQLITE_OK) {
      return false;
    }

    if (sqlite3_bind_int(insert_entity, 11,
                         static_cast<int>(entity.virtual_method_kind())) !=
        SQLITE_OK) {
      return false;
    }

    if (sqlite3_step(insert_entity) != SQLITE_DONE) {
      LOG(ERROR) << "sqlite executing insert_entity failed: "
                 << sqlite3_errmsg(db);
      return false;
    }

    sqlite3_reset(insert_entity);
    sqlite3_clear_bindings(insert_entity);
  }

  return true;
}

bool InsertReferences(sqlite3* db, absl::Span<const Reference> references) {
  sqlite3_stmt* insert_reference = nullptr;
  if (sqlite3_prepare_v2(db, kInsertReference, sizeof(kInsertReference),
                         &insert_reference, nullptr) != SQLITE_OK) {
    LOG(ERROR) << "sqlite compiling prepared statement failed: `"
               << sqlite3_errmsg(db) << "`";
    return false;
  }
  absl::Cleanup cleanup = [insert_reference] {
    sqlite3_finalize(insert_reference);
  };

  for (ReferenceId i = 0; i < references.size(); ++i) {
    const Reference& reference = references[i];
    if (sqlite3_bind_int64(insert_reference, 1, i) != SQLITE_OK ||

        sqlite3_bind_int64(insert_reference, 2, reference.entity_id()) !=
            SQLITE_OK ||

        sqlite3_bind_int64(insert_reference, 3, reference.location_id()) !=
            SQLITE_OK) {
      LOG(ERROR) << "sqlite binding insert_reference failed: `"
                 << sqlite3_errmsg(db) << "`";
      return false;
    }

    if (sqlite3_step(insert_reference) != SQLITE_DONE) {
      LOG(ERROR) << "sqlite executing insert_reference failed: `"
                 << sqlite3_errmsg(db) << "`";
      return false;
    }

    sqlite3_reset(insert_reference);
    sqlite3_clear_bindings(insert_reference);
  }

  return true;
}

bool InsertVirtualMethodLinks(sqlite3* db,
                              absl::Span<const VirtualMethodLink> links) {
  sqlite3_stmt* insert_link = nullptr;
  if (sqlite3_prepare_v2(db, kInsertLink, sizeof(kInsertLink), &insert_link,
                         nullptr) != SQLITE_OK) {
    LOG(ERROR) << "sqlite compiling prepared statement failed: `"
               << sqlite3_errmsg(db) << "`";
    return false;
  }
  absl::Cleanup cleanup = [insert_link] { sqlite3_finalize(insert_link); };

  for (VirtualMethodLinkId i = 0; i < links.size(); ++i) {
    const VirtualMethodLink& link = links[i];
    if (sqlite3_bind_int64(insert_link, 1, i) != SQLITE_OK ||
        sqlite3_bind_int64(insert_link, 2, link.parent()) != SQLITE_OK ||
        sqlite3_bind_int64(insert_link, 3, link.child()) != SQLITE_OK) {
      LOG(ERROR) << "sqlite binding insert_link failed: `" << sqlite3_errmsg(db)
                 << "`";
      return false;
    }

    if (sqlite3_step(insert_link) != SQLITE_DONE) {
      LOG(ERROR) << "sqlite executing insert_link failed: `"
                 << sqlite3_errmsg(db) << "`";
      return false;
    }

    sqlite3_reset(insert_link);
    sqlite3_clear_bindings(insert_link);
  }

  return true;
  return true;
}
}  // anonymous namespace

bool SaveAsSqlite(const FlatIndex& index, const std::string& path,
                  bool enable_expensive_checks) {
  LOG(INFO) << "creating in-memory database";
  const size_t kSqliteMmapSize = 0x1000000000ull;
  if (sqlite3_config(SQLITE_CONFIG_SINGLETHREAD) != SQLITE_OK ||
      sqlite3_config(SQLITE_CONFIG_MMAP_SIZE, kSqliteMmapSize,
                     kSqliteMmapSize) != SQLITE_OK ||
      sqlite3_initialize() != SQLITE_OK) {
    LOG(ERROR) << "sqlite setup failed";
    return false;
  }

  sqlite3* db = nullptr;
  char* error = nullptr;

  if (sqlite3_open(":memory:", &db) != SQLITE_OK) {
    LOG(ERROR) << "sqlite open in-memory database failed: `"
               << sqlite3_errmsg(db) << "`";
    sqlite3_close(db);
    return false;
  }

  absl::Cleanup cleanup = [db] { sqlite3_close(db); };

  if (sqlite3_exec(db, kCreateDb, nullptr, nullptr, &error) != SQLITE_OK) {
    LOG(ERROR) << "sqlite create database failed: `" << error << "`";
    sqlite3_free(error);
    return false;
  }

  if (enable_expensive_checks) {
    if (sqlite3_exec(db, kCreateUniqueIndices, nullptr, nullptr, &error) !=
        SQLITE_OK) {
      LOG(ERROR) << "sqlite creating unique indices failed: `" << error << "`";
      sqlite3_free(error);
      return false;
    }
  }

  LOG(INFO) << "inserting locations";
  if (!InsertLocations(db, index.locations)) {
    return false;
  }

  LOG(INFO) << "inserting entities";
  if (!InsertEntities(db, index.entities)) {
    return false;
  }

  LOG(INFO) << "inserting references";
  if (!InsertReferences(db, index.references)) {
    return false;
  }

  LOG(INFO) << "inserting virtual method links";
  if (!InsertVirtualMethodLinks(db, index.virtual_method_links)) {
    return false;
  }

  if (enable_expensive_checks) {
    // Enable foreign keys and check for foreign key violations.
    if (sqlite3_exec(db, "PRAGMA foreign_keys = ON;", nullptr, nullptr,
                     nullptr) != SQLITE_OK) {
      LOG(ERROR) << "sqlite re-enabling foreign keys failed: `"
                 << sqlite3_errmsg(db) << "`";
      return false;
    }

    sqlite3_stmt* foreign_key_check = nullptr;
    if (sqlite3_prepare_v2(db, "PRAGMA foreign_key_check;", -1,
                           &foreign_key_check, nullptr) != SQLITE_OK) {
      LOG(ERROR) << "sqlite compiling foreign_key_check failed: `"
                 << sqlite3_errmsg(db) << "`";
      return false;
    }
    absl::Cleanup fk_cleanup = [foreign_key_check] {
      sqlite3_finalize(foreign_key_check);
    };
    int rc = sqlite3_step(foreign_key_check);
    if (rc == SQLITE_ROW) {
      LOG(ERROR) << "sqlite foreign key check failed: violations found";
      return false;
    } else if (rc != SQLITE_DONE) {
      LOG(ERROR) << "sqlite foreign key check execution failed: `"
                 << sqlite3_errmsg(db) << "`";
      return false;
    }
  }

  LOG(INFO) << "finalizing database";
  if (sqlite3_exec(db, kFinalizeDb, nullptr, nullptr, &error) != SQLITE_OK) {
    LOG(ERROR) << "database finalization failed: `" << error << "`";
    sqlite3_free(error);
    return false;
  }

  LOG(INFO) << "writing out database";
  sqlite3* file_db = nullptr;
  if (sqlite3_open(path.c_str(), &file_db) != SQLITE_OK) {
    LOG(ERROR) << "sqlite opening file_db failed";
    sqlite3_close(file_db);
    return false;
  }

  bool backup_success = true;
  sqlite3_backup* backup = sqlite3_backup_init(file_db, "main", db, "main");
  if (!backup) {
    backup_success = false;
  }

  if (backup_success) {
    bool step_success = sqlite3_backup_step(backup, -1) == SQLITE_DONE;
    bool finish_success = sqlite3_backup_finish(backup) == SQLITE_OK;
    backup_success = step_success && finish_success;
  }

  if (!backup_success) {
    LOG(ERROR) << "sqlite backup to file_db failed";
  }

  sqlite3_close(file_db);
  return backup_success;
}

}  // namespace indexer
}  // namespace oss_fuzz
