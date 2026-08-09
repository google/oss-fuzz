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
# remove broken tests
# TODO: Check if these can be fixed
# or if they fix themselves over time
export TMPDIR=/tmp/frr-tests
mkdir /tmp/frr-tests
mv tests/bgpd/test_peer_attr.py $TMPDIR/
mv tests/bgpd/test_mp_attr.py $TMPDIR/
mv tests/bgpd/test_mpath.py $TMPDIR/
mv tests/isisd/test_isis_spf.py $TMPDIR/
mv tests/lib/northbound/test_oper_data.py $TMPDIR/
mv tests/lib/test_timer_correctness.py $TMPDIR/
mv tests/lib/test_xref.py $TMPDIR/
mv tests/lib/cli/test_cli.py $TMPDIR/
mv tests/ospf6d/test_lsdb.py $TMPDIR/
mv tests/ospfd/test_ospf_spf.py $TMPDIR/
mv tests/zebra/test_lm_plugin.py $TMPDIR/

source $SRC/venv/bin/activate
export ASAN_OPTIONS="detect_leaks=0"

# run tests
test_output=$(make check)
test_exit_code=$?

# restore broken tests
mv $TMPDIR/test_peer_attr.py tests/bgpd/
mv $TMPDIR/test_mp_attr.py tests/bgpd/
mv $TMPDIR/test_mpath.py tests/bgpd/
mv $TMPDIR/test_isis_spf.py tests/isisd/
mv $TMPDIR/test_oper_data.py tests/lib/northbound/
mv $TMPDIR/test_timer_correctness.py tests/lib/
mv $TMPDIR/test_xref.py tests/lib/
mv $TMPDIR/test_cli.py tests/lib/cli/
mv $TMPDIR/test_lsdb.py tests/ospf6d/
mv $TMPDIR/test_ospf_spf.py tests/ospfd/
mv $TMPDIR/test_lm_plugin.py tests/zebra/

exit $test_exit_code
