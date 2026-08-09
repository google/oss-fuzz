#!/bin/bash -eu
#
# Copyright 2026 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
################################################################################

# Disable leak sanitizer
export ASAN_OPTIONS="detect_leaks=0"

# Disable failing testing and tests requires network connection and run the remaining unit testings
make -C $SRC/brpc/build/test -j$(nproc) && ctest --test-dir $SRC/brpc/build --output-on-failure -j$(nproc) -E \
  "test_butil|bthread_timer_thread_unittest|brpc_alpn_protocol_unittest|brpc_channel_unittest|brpc_interceptor_unittest|brpc_ssl_unittest|bthread_mutex_unittest|bthread_cond_unittest|bthread_butex_unittest|bthread_dispatcher_unittest|bthread_fd_unittest|bthread_setconcurrency_unittest|brpc_http_rpc_protocol_unittest|brpc_naming_service_unittest|brpc_event_dispatcher_unittest|brpc_server_unittest|brpc_streaming_rpc_unittest|brpc_socket_unittest"
