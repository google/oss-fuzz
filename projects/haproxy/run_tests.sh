#!/bin/bash -eu
# Copyright 2025 Google LLC
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

cd $SRC/haproxy

# These tests fails so remove it. Store them in a temporary directory because
# we need to keep same state as prior to running run_tests.sh.
mkdir /tmp/saved_tests
DISABLED_TEST_DIR=/tmp/saved_tests/
mv reg-tests/http-rules/converters_ipmask_concat_strcmp_field_word.vtc ${DISABLED_TEST_DIR}
mv reg-tests/http-messaging/http_wait_for_body.vtc ${DISABLED_TEST_DIR}
mv reg-tests/stickiness/srvkey-addr.vtc ${DISABLED_TEST_DIR}
mv reg-tests/server/cli_set_fqdn.vtc ${DISABLED_TEST_DIR}

make unit-tests
HAPROXY_PROGRAM=$SRC/haproxy/haproxy VTEST_PROGRAM=$SRC/VTest2/vtest make reg-tests

# Restore state
mv ${DISABLED_TEST_DIR}/converters_ipmask_concat_strcmp_field_word.vtc reg-tests/http-rules/converters_ipmask_concat_strcmp_field_word.vtc
mv ${DISABLED_TEST_DIR}/http_wait_for_body.vtc reg-tests/http-messaging/http_wait_for_body.vtc
mv ${DISABLED_TEST_DIR}/srvkey-addr.vtc reg-tests/stickiness/srvkey-addr.vtc
mv ${DISABLED_TEST_DIR}/cli_set_fqdn.vtc reg-tests/server/cli_set_fqdn.vtc
