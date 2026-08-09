// Copyright 2025 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
////////////////////////////////////////////////////////////////////////////////
#include <string>
#include "fuzzer/FuzzedDataProvider.h"

#include "mhd_sys_options.h"
#include "microhttpd2.h"
#include "mhd_connection.h"
#include "mhd_daemon.h"
#include "mhd_post_parser.h"
#include "request_funcs.h"


extern struct mhd_MemoryPool *g_pool;
extern const size_t g_pool_size;
extern std::string g_mpart_boundary;

void destroy_global_pool();
extern const struct MHD_UploadAction kContinueAction;
extern const struct MHD_UploadAction kSuspend;
extern const struct MHD_UploadAction kAbort;

const struct MHD_UploadAction * dummy_reader(struct MHD_Request*, void*, const struct MHD_String*,
             const struct MHD_StringNullable*, const struct MHD_StringNullable*,
             const struct MHD_StringNullable*, size_t, const void*,
             uint_fast64_t, enum MHD_Bool);
const struct MHD_UploadAction * dummy_done(struct MHD_Request*, void*, enum MHD_PostParseResult);

void init_daemon_connection(FuzzedDataProvider& fdp, MHD_Daemon& d, MHD_Connection& c);
void init_connection_buffer(FuzzedDataProvider& fdp, MHD_Connection& c);
void init_parsing_configuration(FuzzedDataProvider& fdp, MHD_Connection& c);
void prepare_headers_and_parse(MHD_Connection& connection, size_t size);
void prepare_body_and_process(MHD_Connection& connection, std::string& body, size_t body_size, bool use_stream_body);
void final_cleanup(MHD_Connection& connection, MHD_Daemon& daemon);

void mark_post_parse_ready(MHD_Connection& connection);
bool is_post_parse_ready(const MHD_Connection& connection);
void clear_post_parse_ready(const MHD_Connection& connection);
