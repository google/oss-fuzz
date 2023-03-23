#!/bin/bash -eu
# Copyright 2023 Google LLC
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
./bootstrap.sh tests
./configure CC="$CC" CFLAGS="$CFLAGS" LDFLAGS="$CFLAGS" --enable-server --with-mysql
make dbschema
make all

zbxeval=fuzz-zbxeval
zbxhttp=fuzz-zbxhttp
zbxjson=fuzz-zbxjson
EXTCFLAGS="-Wall -DHAVE_CONFIG_H"
INC="-I include/ -I include/common/"

zbxevalLibFLAGS="src/libs/zbxeval/libzbxeval.a src/libs/zbxserialize/libzbxserialize.a src/libs/zbxtrends/libzbxtrends.a src/libs/zbxsysinfo/libzbxserversysinfo.a src/libs/zbxsysinfo/common/libcommonsysinfo.a src/libs/zbxsysinfo/simple/libsimplesysinfo.a src/libs/zbxshmem/libzbxshmem.a src/libs/zbxself/libzbxself.a src/libs/zbxtimekeeper/libzbxtimekeeper.a src/libs/zbxmedia/libzbxmedia.a src/libs/zbxserver/libzbxserver.a src/libs/zbxavailability/libzbxavailability.a src/libs/zbxtagfilter/libzbxtagfilter.a src/libs/zbxconnector/libzbxconnector.a src/libs/zbxcomms/libzbxcomms.a src/libs/zbxcompress/libzbxcompress.a src/libs/zbxcrypto/libzbxcrypto.a src/libs/zbxcommshigh/libzbxcommshigh.a src/libs/zbxjson/libzbxjson.a src/libs/zbxvariant/libzbxvariant.a src/libs/zbxregexp/libzbxregexp.a src/libs/zbxipcservice/libzbxipcservice.a src/libs/zbxexec/libzbxexec.a src/libs/zbxicmpping/libzbxicmpping.a src/libs/zbxdbupgrade/libzbxdbupgrade.a src/libs/zbxdb/libzbxdb.a src/libs/zbxmodules/libzbxmodules.a src/libs/zbxtasks/libzbxtasks.a src/libs/zbxhistory/libzbxhistory.a src/zabbix_server/libzbxserver.a src/libs/zbxdbhigh/libzbxdbhigh.a src/libs/zbxdbwrap/libzbxdbwrap.a src/libs/zbxvault/libzbxvault.a src/libs/zbxkvs/libzbxkvs.a src/libs/zbxhttp/libzbxhttp.a src/libs/zbxexpr/libzbxexpr.a src/libs/zbxlog/libzbxlog.a src/libs/zbxconf/libzbxconf.a src/libs/zbxthreads/libzbxthreads.a src/libs/zbxtime/libzbxtime.a src/libs/zbxmutexs/libzbxmutexs.a src/libs/zbxprof/libzbxprof.a src/libs/zbxalgo/libzbxalgo.a src/libs/zbxip/libzbxip.a src/libs/zbxnix/libzbxnix.a src/libs/zbxstr/libzbxstr.a src/libs/zbxnum/libzbxnum.a src/libs/zbxcommon/libzbxcommon.a -l:libevent.a -l:libevent_pthreads.a"
zbxhttpLibFLAGS="src/libs/zbxhttp/libzbxhttp.a src/libs/zbxaudit/libzbxaudit.a src/libs/zbxparam/libzbxparam.a src/libs/zbxexpr/libzbxexpr.a src/libs/zbxnix/libzbxnix.a src/libs/zbxnum/libzbxnum.a src/libs/zbxstr/libzbxstr.a src/libs/zbxcommon/libzbxcommon.a src/libs/zbxlog/libzbxlog.a src/libs/zbxconf/libzbxconf.a src/libs/zbxthreads/libzbxthreads.a src/libs/zbxtime/libzbxtime.a src/libs/zbxmutexs/libzbxmutexs.a src/libs/zbxprof/libzbxprof.a src/libs/zbxalgo/libzbxalgo.a src/libs/zbxip/libzbxip.a src/libs/zbxnix/libzbxnix.a src/libs/zbxstr/libzbxstr.a src/libs/zbxnum/libzbxnum.a src/libs/zbxcacheconfig/libzbxcacheconfig.a src/libs/zbxcachehistory/libzbxcachehistory.a src/libs/zbxcachevalue/libzbxcachevalue.a src/libs/zbxcommon/libzbxcommon.a -l:libevent.a -l:libevent_pthreads.a"
zbxjsonLibFLAGS="src/libs/zbxjson/libzbxjson.a src/libs/zbxvariant/libzbxvariant.a src/libs/zbxregexp/libzbxregexp.a src/libs/zbxcomms/libzbxcomms.a src/libs/zbxcompress/libzbxcompress.a src/libs/zbxcrypto/libzbxcrypto.a src/libs/zbxlog/libzbxlog.a src/libs/zbxconf/libzbxconf.a src/libs/zbxthreads/libzbxthreads.a src/libs/zbxtime/libzbxtime.a src/libs/zbxmutexs/libzbxmutexs.a src/libs/zbxprof/libzbxprof.a src/libs/zbxalgo/libzbxalgo.a src/libs/zbxip/libzbxip.a src/libs/zbxnix/libzbxnix.a src/libs/zbxstr/libzbxstr.a src/libs/zbxnum/libzbxnum.a src/libs/zbxcommon/libzbxcommon.a -l:libevent.a -l:libevent_pthreads.a -lpcre"

$CC $CFLAGS $EXTCFLAGS $INC -c "$zbxeval".c
$CC $CFLAGS $EXTCFLAGS $INC -c "$zbxhttp".c
$CC $CFLAGS $EXTCFLAGS $INC -c "$zbxjson".c

$CXX $CFLAGS -o $zbxeval $zbxeval.o $LIB_FUZZING_ENGINE $zbxevalLibFLAGS
$CXX $CFLAGS -o $zbxhttp $zbxhttp.o $LIB_FUZZING_ENGINE $zbxhttpLibFLAGS
$CXX $CFLAGS -o $zbxjson $zbxjson.o $LIB_FUZZING_ENGINE $zbxjsonLibFLAGS

cp $zbxeval $OUT/$zbxeval
cp $zbxhttp $OUT/$zbxhttp
cp $zbxjson $OUT/$zbxjson

cp $SRC/oss-fuzz-bloat/zabbix/* $OUT/.
