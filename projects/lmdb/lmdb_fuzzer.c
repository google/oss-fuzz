// Copyright 2021 Google LLC
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
//
////////////////////////////////////////////////////////////////////////////////


#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include "lmdb.h"

int LLVMFuzzerTestOneInput(const uint8_t *input, size_t size){
	if (size<5) {
		return 0;
	}
	char *new_str = (char *)malloc(size+1);
	if (new_str == NULL){
		return 0;
	}
	memcpy(new_str, input, size);
	new_str[size] = '\0';

	int rc;
	MDB_env *env;
	MDB_dbi dbi;
	MDB_val key, data;
	MDB_stat mst;
	MDB_txn *txn;
	MDB_cursor *cursor;
	char sval[size+1];

	rc = mdb_env_create(&env);
	rc = mdb_env_open(env, "/tmp", 0, 0664);
	rc = mdb_txn_begin(env, NULL, 0, &txn);
	rc = mdb_dbi_open(txn, NULL, MDB_CREATE, &dbi);

	key.mv_size = sizeof(int);
	key.mv_data = sval;
	data.mv_size = sizeof(sval);
	data.mv_data = sval;

	sprintf(sval, "%s", new_str);
	rc = mdb_put(txn, dbi, &key, &data, 0);
	rc = mdb_txn_commit(txn);
	rc = mdb_env_stat(env, &mst);
	if (rc) {
		goto leave;
	}
	rc = mdb_txn_begin(env, NULL, MDB_RDONLY, &txn);
	rc = mdb_cursor_open(txn, dbi, &cursor);
	rc = mdb_cursor_get(cursor, &key, &data, MDB_NEXT);
	mdb_cursor_close(cursor);
	mdb_txn_abort(txn);
leave:
	mdb_dbi_close(env, dbi);
	mdb_env_close(env);
	free(new_str);
	return 0;
}
