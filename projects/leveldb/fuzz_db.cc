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

#include "leveldb/db.h"
#include <stdio.h>
#include <stdlib.h>
#include <string>
#include <string.h>
#include <filesystem>

// Helper function to provide random strings for the fuzzer
std::string get_string(const uint8_t **data, size_t *remaining) {
    if (*remaining == 0) {
       return std::string("");   
    }
    uint8_t s_size = (*data)[0];

    // if s_size is more than we have available, do not use s_size
    if (s_size > *remaining) {
       std::string s1(reinterpret_cast<const char*>(*data), *remaining);
       *data += *remaining;
       *remaining = 0;
       return s1;
    }

    std::string s1(reinterpret_cast<const char*>(*data), s_size);
    *remaining -= s_size;
    return s1;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  // We need at least one byte
  if (size == 0) {
    return 0;
  }

  leveldb::DB* db;
  leveldb::Options options;
  options.create_if_missing = true;
  leveldb::Status status = leveldb::DB::Open(options, "/tmp/testdb", &db);

  // for random string generation
  const uint8_t *curr_offset = data; 
  size_t curr_size = size;

  std::string value;

  // perform a sequence of calls on our db instance
  int max_iter = (int)data[0];
  for(int i=0; i < max_iter && i < size; i++) {
    #define SIZE_OF_FUNCS 8
    char c = data[i] % SIZE_OF_FUNCS;

    if(c == 0) {  // PUT
        std::string tmp1 = get_string(&curr_offset, &curr_size);
        std::string tmp2 = get_string(&curr_offset, &curr_size);
      db->Put(leveldb::WriteOptions(), tmp1, tmp2);
    } 
    else if(c == 1) { // Get
        std::string tmp3 = get_string(&curr_offset, &curr_size);
      db->Get(leveldb::ReadOptions(), tmp3, &value);
    } 
    else if (c == 2) { // Delete
      std::string tmp4 = get_string(&curr_offset, &curr_size);
      db->Delete(leveldb::WriteOptions(), tmp4);
    }
    else if (c == 3) { // GetProperty
      std::string prop;
      std::string tmp = get_string(&curr_offset, &curr_size);
      db->GetProperty(tmp, &prop);
    }
    else if(c == 4) { // Iterator
      leveldb::Iterator* it = db->NewIterator(leveldb::ReadOptions());
      for (it->SeekToFirst(); it->Valid(); it->Next()) {
        continue;
      }
      delete it;
    } 
    else if(c == 5) { // GetSnapshot and Release Snapshot
      leveldb::ReadOptions snapshot_options;
      snapshot_options.snapshot = db->GetSnapshot();
      leveldb::Iterator* it = db->NewIterator(snapshot_options);
      db->ReleaseSnapshot(snapshot_options.snapshot);
    } 
    else if(c == 6) { // Open and close DB
      delete db;
      status = leveldb::DB::Open(options, "/tmp/testdb", &db);
    }
    else if (c == 7) { 
      std::string tmp1 = get_string(&curr_offset, &curr_size);
      std::string tmp2 = get_string(&curr_offset, &curr_size);
      leveldb::Slice s1 =tmp1;
      leveldb::Slice s2 = tmp2;
      db->CompactRange(&s1, &s2);
    }
  }

  // Cleanup DB
  delete db;
  std::__fs::filesystem::remove_all("/tmp/testdb");
  return 0;
}
