/* Copyright 2020 Google Inc.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

      http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/


#include <cstdint>
#include <cstddef>
#include <filesystem>
#include <memory>
#include <string>

#include "leveldb/db.h"
#include "leveldb/iterator.h"
#include "leveldb/options.h"
#include "leveldb/status.h"

#include <fuzzer/FuzzedDataProvider.h>

namespace {

// Deletes the database directory when going out of scope.
class AutoDbDeleter {
 public:
  static constexpr char kDbPath[] = "/tmp/testdb";

  AutoDbDeleter() = default;

  AutoDbDeleter(const AutoDbDeleter&) = delete;
  AutoDbDeleter& operator=(const AutoDbDeleter&) = delete;

  ~AutoDbDeleter() {
    std::__fs::filesystem::remove_all(kDbPath);
  }
};

// static
constexpr char AutoDbDeleter::kDbPath[];

// Returns nullptr (a falsey unique_ptr) if opening fails.
std::unique_ptr<leveldb::DB> OpenDB() {
  leveldb::Options options;
  options.create_if_missing = true;

  leveldb::DB* db_ptr;
  leveldb::Status status =
      leveldb::DB::Open(options, AutoDbDeleter::kDbPath, &db_ptr);
  if (!status.ok())
    return nullptr;

  return std::unique_ptr<leveldb::DB>(db_ptr);
}

enum class FuzzOp {
  kPut = 0,
  kGet = 1,
  kDelete = 2,
  kGetProperty = 3,
  kIterate = 4,
  kGetReleaseSnapshot = 5,
  kReopenDb = 6,
  kCompactRange = 7,
  // Add new values here.

  // When adding new values, update to the last value above.
  kMaxValue = kCompactRange,
};

}  // namespace

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  // Must occur before `db` so the deletion doesn't happen while the DB is open.
  AutoDbDeleter db_deleter;

  std::unique_ptr<leveldb::DB> db = OpenDB();
  if (!db.get())
    return 0;

  // Perform a sequence of operations on the database.
  FuzzedDataProvider fuzzed_data(data, size);
  while (fuzzed_data.remaining_bytes() != 0) {
    FuzzOp fuzz_op = fuzzed_data.ConsumeEnum<FuzzOp>();

    switch (fuzz_op) {
    case FuzzOp::kPut: {
      std::string key = fuzzed_data.ConsumeRandomLengthString();
      std::string value = fuzzed_data.ConsumeRandomLengthString();
      db->Put(leveldb::WriteOptions(), key, value);
      break;
    }
    case FuzzOp::kGet: {
      std::string key = fuzzed_data.ConsumeRandomLengthString();
      std::string value;
      db->Get(leveldb::ReadOptions(), key, &value);
      break;
    }
    case FuzzOp::kDelete: {
      std::string key = fuzzed_data.ConsumeRandomLengthString();
      db->Delete(leveldb::WriteOptions(), key);
      break;
    }
    case FuzzOp::kGetProperty: {
      std::string name = fuzzed_data.ConsumeRandomLengthString();
      std::string value;
      db->GetProperty(name, &value);
      break;
    }
    case FuzzOp::kIterate: {
      std::unique_ptr<leveldb::Iterator> it(
          db->NewIterator(leveldb::ReadOptions()));
      for (it->SeekToFirst(); it->Valid(); it->Next())
        continue;
    }
    case FuzzOp::kGetReleaseSnapshot: {
      leveldb::ReadOptions snapshot_options;
      snapshot_options.snapshot = db->GetSnapshot();
      std::unique_ptr<leveldb::Iterator> it(db->NewIterator(snapshot_options));
      db->ReleaseSnapshot(snapshot_options.snapshot);
    }
    case FuzzOp::kReopenDb: {
      // The database must be closed before attempting to reopen it. Otherwise,
      // the open will fail due to exclusive locking.
      db.reset();
      db = OpenDB();
      if (!db)
        return 0;  // Reopening the database failed.
      break;
    }
    case FuzzOp::kCompactRange: {
      std::string begin_key = fuzzed_data.ConsumeRandomLengthString();
      std::string end_key =  fuzzed_data.ConsumeRandomLengthString();
      leveldb::Slice begin_slice(begin_key);
      leveldb::Slice end_slice(end_key);
      db->CompactRange(&begin_slice, &end_slice);
      break;
    }
    }
  }

  return 0;
}
