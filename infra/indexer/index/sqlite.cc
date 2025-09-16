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
#include <utility>

#include "indexer/index/types.h"
#include "absl/cleanup/cleanup.h"
#include "absl/log/log.h"
#include "absl/types/span.h"
#include "sqlite3.h"

#define SCHEMA_VERSION "4"

namespace oss_fuzz {
namespace indexer {
namespace {

// Note: We could in principle enforce UNIQUE constraints on `reference` foreign
// key pairs, as well as those of `virtual_method_link` and
// `entity_translation_unit` (as an extreme, non-ID fields of e.g. `location`
// could also be made into a UNIQUE tuple). But those are unique by construction
// now and we hope to avoid the overhead of checking those constraints.

const char kCreateDb[] =
    "PRAGMA foreign_keys = ON;\n"
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
    "  parent_entity_id);\n";

const char kCreateIncrementalIndexingSupportTables[] =
    "CREATE TABLE translation_unit(\n"
    "  id       INTEGER PRIMARY KEY,\n"
    "  path     TEXT);\n"
    "\n"
    "CREATE TABLE entity_translation_unit(\n"
    "  id           INTEGER PRIMARY KEY,\n"
    "  entity_id    INT NOT NULL,\n"
    "  tu_id        INT NOT NULL,\n"
    "  FOREIGN KEY (entity_id) REFERENCES entity(id),\n"
    "  FOREIGN KEY (tu_id) REFERENCES translation_unit(id));\n"
    "\n"
    "CREATE TABLE reference_translation_unit(\n"
    "  id              INTEGER PRIMARY KEY,\n"
    "  reference_id    INT NOT NULL,\n"
    "  tu_id           INT NOT NULL,\n"
    "  FOREIGN KEY (reference_id) REFERENCES reference(id),\n"
    "  FOREIGN KEY (tu_id) REFERENCES translation_unit(id));\n";

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

const char kInsertTranslationUnit[] =
    "INSERT INTO translation_unit\n"
    "  (id, path)\n"
    "  VALUES (?1, ?2);";

const char kInsertEntityTranslationUnit[] =
    "INSERT INTO entity_translation_unit\n"
    "  (id, entity_id, tu_id)\n"
    "  VALUES (?1, ?2, ?3);";

const char kInsertReferenceTranslationUnit[] =
    "INSERT INTO reference_translation_unit\n"
    "  (id, reference_id, tu_id)\n"
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
      sqlite3_finalize(insert_location);
      return false;
    }

    if (sqlite3_step(insert_location) != SQLITE_DONE) {
      LOG(ERROR) << "sqlite executing insert_entity failed: `"
                 << sqlite3_errmsg(db) << "`";
      sqlite3_finalize(insert_location);
      return false;
    }

    sqlite3_reset(insert_location);
    sqlite3_clear_bindings(insert_location);
  }

  sqlite3_finalize(insert_location);
  return true;
}

bool InsertEntities(sqlite3* db, absl::Span<const Entity> entities) {
  // `substitute_entity_id` foreign key can refer to a yet-unadded entity.
  if (sqlite3_exec(db, "PRAGMA foreign_keys = OFF;", nullptr, nullptr,
                   nullptr) != SQLITE_OK) {
    LOG(ERROR) << "sqlite disabling foreign keys failed: `"
               << sqlite3_errmsg(db) << "`";
    return false;
  }

  sqlite3_stmt* insert_entity = nullptr;
  if (sqlite3_prepare_v2(db, kInsertEntity, sizeof(kInsertEntity),
                         &insert_entity, nullptr) != SQLITE_OK) {
    LOG(ERROR) << "sqlite compiling prepared statement failed: `"
               << sqlite3_errmsg(db) << "`";
    return false;
  }

  absl::Cleanup cleanup = [db, insert_entity] {
    LOG(ERROR) << "sqlite binding insert_entity failed: `" << sqlite3_errmsg(db)
               << "`";
    sqlite3_finalize(insert_entity);
  };

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
      sqlite3_finalize(insert_entity);
      return false;
    }

    sqlite3_reset(insert_entity);
    sqlite3_clear_bindings(insert_entity);
  }

  std::move(cleanup).Cancel();
  sqlite3_finalize(insert_entity);

  if (sqlite3_exec(db, "PRAGMA foreign_keys = ON;", nullptr, nullptr,
                   nullptr) != SQLITE_OK) {
    LOG(ERROR) << "sqlite re-enabling foreign keys failed: `"
               << sqlite3_errmsg(db) << "`";
    return false;
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

  for (ReferenceId i = 0; i < references.size(); ++i) {
    const Reference& reference = references[i];
    if (sqlite3_bind_int64(insert_reference, 1, i) != SQLITE_OK ||

        sqlite3_bind_int64(insert_reference, 2, reference.entity_id()) !=
            SQLITE_OK ||

        sqlite3_bind_int64(insert_reference, 3, reference.location_id()) !=
            SQLITE_OK) {
      LOG(ERROR) << "sqlite binding insert_reference failed: `"
                 << sqlite3_errmsg(db) << "`";
      sqlite3_finalize(insert_reference);
      return false;
    }

    if (sqlite3_step(insert_reference) != SQLITE_DONE) {
      LOG(ERROR) << "sqlite executing insert_reference failed: `"
                 << sqlite3_errmsg(db) << "`";
      sqlite3_finalize(insert_reference);
      return false;
    }

    sqlite3_reset(insert_reference);
    sqlite3_clear_bindings(insert_reference);
  }

  sqlite3_finalize(insert_reference);
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

  for (VirtualMethodLinkId i = 0; i < links.size(); ++i) {
    const VirtualMethodLink& link = links[i];
    if (sqlite3_bind_int64(insert_link, 1, i) != SQLITE_OK ||
        sqlite3_bind_int64(insert_link, 2, link.parent()) != SQLITE_OK ||
        sqlite3_bind_int64(insert_link, 3, link.child()) != SQLITE_OK) {
      LOG(ERROR) << "sqlite binding insert_link failed: `" << sqlite3_errmsg(db)
                 << "`";
      sqlite3_finalize(insert_link);
      return false;
    }

    if (sqlite3_step(insert_link) != SQLITE_DONE) {
      LOG(ERROR) << "sqlite executing insert_link failed: `"
                 << sqlite3_errmsg(db) << "`";
      sqlite3_finalize(insert_link);
      return false;
    }

    sqlite3_reset(insert_link);
    sqlite3_clear_bindings(insert_link);
  }

  sqlite3_finalize(insert_link);
  return true;
}

bool InsertTranslationUnits(
    sqlite3* db, absl::Span<const TranslationUnit> translation_units) {
  sqlite3_stmt* insert_tu = nullptr;
  if (sqlite3_prepare_v2(db, kInsertTranslationUnit,
                         sizeof(kInsertTranslationUnit), &insert_tu,
                         nullptr) != SQLITE_OK) {
    LOG(ERROR) << "sqlite compiling prepared statement failed: `"
               << sqlite3_errmsg(db) << "`";
    return false;
  }

  for (TranslationUnitId i = 0; i < translation_units.size(); ++i) {
    const TranslationUnit& tu = translation_units[i];
    if (sqlite3_bind_int64(insert_tu, 1, i) != SQLITE_OK ||
        sqlite3_bind_text(insert_tu, 2, tu.index_path().data(),
                          tu.index_path().size(), SQLITE_STATIC) != SQLITE_OK) {
      LOG(ERROR) << "sqlite binding insert_tu failed: `" << sqlite3_errmsg(db)
                 << "`";
      sqlite3_finalize(insert_tu);
      return false;
    }

    if (sqlite3_step(insert_tu) != SQLITE_DONE) {
      LOG(ERROR) << "sqlite executing insert_tu failed: `" << sqlite3_errmsg(db)
                 << "`";
      sqlite3_finalize(insert_tu);
      return false;
    }

    sqlite3_reset(insert_tu);
    sqlite3_clear_bindings(insert_tu);
  }

  sqlite3_finalize(insert_tu);
  return true;
}

bool InsertEntityTranslationUnits(
    sqlite3* db,
    absl::Span<const EntityTranslationUnit> entity_translation_units) {
  sqlite3_stmt* insert_entity_tu = nullptr;
  if (sqlite3_prepare_v2(db, kInsertEntityTranslationUnit,
                         sizeof(kInsertEntityTranslationUnit),
                         &insert_entity_tu, nullptr) != SQLITE_OK) {
    LOG(ERROR) << "sqlite compiling prepared statement failed: `"
               << sqlite3_errmsg(db) << "`";
    return false;
  }

  for (EntityTranslationUnitId i = 0; i < entity_translation_units.size();
       ++i) {
    const EntityTranslationUnit& entity_tu = entity_translation_units[i];
    if (sqlite3_bind_int64(insert_entity_tu, 1, i) != SQLITE_OK ||
        sqlite3_bind_int64(insert_entity_tu, 2, entity_tu.entity_id()) !=
            SQLITE_OK ||
        sqlite3_bind_int64(insert_entity_tu, 3, entity_tu.tu_id()) !=
            SQLITE_OK) {
      LOG(ERROR) << "sqlite binding insert_entity_tu failed: `"
                 << sqlite3_errmsg(db) << "`";
      sqlite3_finalize(insert_entity_tu);
      return false;
    }

    if (sqlite3_step(insert_entity_tu) != SQLITE_DONE) {
      LOG(ERROR) << "sqlite executing insert_entity_tu failed: `"
                 << sqlite3_errmsg(db) << "`";
      sqlite3_finalize(insert_entity_tu);
      return false;
    }

    sqlite3_reset(insert_entity_tu);
    sqlite3_clear_bindings(insert_entity_tu);
  }

  sqlite3_finalize(insert_entity_tu);
  return true;
}

bool InsertReferenceTranslationUnits(
    sqlite3* db,
    absl::Span<const ReferenceTranslationUnit> reference_translation_units) {
  sqlite3_stmt* insert_reference_tu = nullptr;
  if (sqlite3_prepare_v2(db, kInsertReferenceTranslationUnit,
                         sizeof(kInsertReferenceTranslationUnit),
                         &insert_reference_tu, nullptr) != SQLITE_OK) {
    LOG(ERROR) << "sqlite compiling prepared statement failed: `"
               << sqlite3_errmsg(db) << "`";
    return false;
  }

  for (ReferenceTranslationUnitId i = 0; i < reference_translation_units.size();
       ++i) {
    const ReferenceTranslationUnit& reference_tu =
        reference_translation_units[i];
    if (sqlite3_bind_int64(insert_reference_tu, 1, i) != SQLITE_OK ||
        sqlite3_bind_int64(insert_reference_tu, 2,
                           reference_tu.reference_id()) != SQLITE_OK ||
        sqlite3_bind_int64(insert_reference_tu, 3, reference_tu.tu_id()) !=
            SQLITE_OK) {
      LOG(ERROR) << "sqlite binding insert_reference_tu failed: `"
                 << sqlite3_errmsg(db) << "`";
      sqlite3_finalize(insert_reference_tu);
      return false;
    }

    if (sqlite3_step(insert_reference_tu) != SQLITE_DONE) {
      LOG(ERROR) << "sqlite executing insert_reference_tu failed: `"
                 << sqlite3_errmsg(db) << "`";
      sqlite3_finalize(insert_reference_tu);
      return false;
    }

    sqlite3_reset(insert_reference_tu);
    sqlite3_clear_bindings(insert_reference_tu);
  }

  sqlite3_finalize(insert_reference_tu);
  return true;
}
}  // anonymous namespace

bool SaveAsSqlite(const FlatIndex& index, const std::string& path) {
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
  if (sqlite3_open(":memory:", &db) != SQLITE_OK ||
      sqlite3_exec(db, kCreateDb, nullptr, nullptr, &error) != SQLITE_OK) {
    LOG(ERROR) << "sqlite create database failed: `" << error << "`";
    sqlite3_close(db);
    return false;
  }

  LOG(INFO) << "inserting locations";
  if (!InsertLocations(db, index.locations)) {
    sqlite3_close(db);
    return false;
  }

  LOG(INFO) << "inserting entities";
  if (!InsertEntities(db, index.entities)) {
    sqlite3_close(db);
    return false;
  }

  LOG(INFO) << "inserting references";
  if (!InsertReferences(db, index.references)) {
    sqlite3_close(db);
    return false;
  }

  LOG(INFO) << "inserting virtual method links";
  if (!InsertVirtualMethodLinks(db, index.virtual_method_links)) {
    sqlite3_close(db);
    return false;
  }

  if (index.incremental_indexing_metadata.has_value()) {
    const IncrementalIndexingMetadata& metadata =
        *index.incremental_indexing_metadata;

    LOG(INFO) << "creating incremental indexing support tables";
    if (sqlite3_exec(db, kCreateIncrementalIndexingSupportTables, nullptr,
                     nullptr, &error) != SQLITE_OK) {
      LOG(ERROR) << "incremental indexing support table creation failed: `"
                 << error << "`";
      sqlite3_close(db);
      return false;
    }

    LOG(INFO) << "inserting translation units";
    if (!InsertTranslationUnits(db, metadata.translation_units)) {
      sqlite3_close(db);
      return false;
    }

    LOG(INFO) << "inserting entity - translation unit pairs";
    if (!InsertEntityTranslationUnits(db, metadata.entity_translation_units)) {
      sqlite3_close(db);
      return false;
    }

    LOG(INFO) << "inserting reference - translation unit pairs";
    if (!InsertReferenceTranslationUnits(
            db, metadata.reference_translation_units)) {
      sqlite3_close(db);
      return false;
    }
  }

  LOG(INFO) << "finalizing database";
  if (sqlite3_exec(db, kFinalizeDb, nullptr, nullptr, &error) != SQLITE_OK) {
    LOG(ERROR) << "database finalization failed: `" << error << "`";
    sqlite3_close(db);
    return false;
  }

  LOG(INFO) << "writing out database";
  sqlite3* file_db = nullptr;
  if (sqlite3_open(path.c_str(), &file_db) != SQLITE_OK) {
    LOG(ERROR) << "sqlite opening file_db failed";
    sqlite3_close(db);
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
  sqlite3_close(db);
  return backup_success;
}

}  // namespace indexer
}  // namespace oss_fuzz
