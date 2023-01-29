#!/bin/bash -eu
# Copyright 2021 Google LLC
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

# Build spdk
export LDFLAGS="${CFLAGS}"
./scripts/pkgdep.sh
./configure --without-shared
make -j$(nproc)

# Build fuzzers
$CXX $CXXFLAGS -I/src/spdk -I/src/spdk/include \
        -fPIC -c $SRC/parse_json_fuzzer.cc \
        -o parse_json_fuzzer.o

$CXX $CXXFLAGS $LIB_FUZZING_ENGINE \
        parse_json_fuzzer.o -o $OUT/parse_json_fuzzer \
        /src/spdk/build/lib/libspdk_env_dpdk.a \
        /src/spdk/build/lib/libspdk_json.a 

set +e
projectName=spdk
# read the csv file
while IFS="," read -r first_col src_path dst_path; do    
    # check if first_col equals the projectName
    if [ "$src_path" == NOT_FOUND ]; then
        continue
    fi
    if [ "$first_col" == "$projectName" ]; then
        work_dir=`dirname $dst_path`
        mkdir -p $work_dir
        cp -v $src_path $dst_path || true
    fi
done < /src/headerfiles.csv
    
for outfile in $(find /src/*/fuzzdrivers -name "*.c"); do
outexe=${outfile%.*}
echo $outexe
/usr/local/bin/clang-15 -isystem /usr/local/lib/clang/15.0.0/include -isystem /usr/local/include -isystem /usr/include/x86_64-linux-gnu -isystem /usr/include -fsanitize=address -fsanitize=fuzzer -I/work/include -O1 -fno-omit-frame-pointer -gline-tables-only -DFUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION -fsanitize=address -fsanitize-address-use-after-scope -fsanitize=fuzzer-no-link -fPIC -I/src/spdk/include $outfile /src/spdk/build/lib/libspdk_event_iobuf.a /src/spdk/build/lib/libspdk_trace_parser.a /src/spdk/build/lib/libspdk_event_scheduler.a /src/spdk/build/lib/libspdk_nbd.a /src/spdk/build/lib/libspdk_bdev_nvme.a /src/spdk/build/lib/libspdk_vhost.a /src/spdk/build/lib/libspdk_vfio_user.a /src/spdk/build/lib/libspdk_event.a /src/spdk/build/lib/libspdk_bdev_malloc.a /src/spdk/build/lib/libspdk_nvme.a /src/spdk/build/lib/libspdk_ftl.a /src/spdk/build/lib/libspdk_ioat.a /src/spdk/build/lib/libspdk_scheduler_dpdk_governor.a /src/spdk/build/lib/libspdk_sock.a /src/spdk/build/lib/libspdk_accel_ioat.a /src/spdk/build/lib/libspdk_json.a /src/spdk/build/lib/libspdk_blob.a /src/spdk/build/lib/libspdk_bdev_zone_block.a /src/spdk/build/lib/libspdk_bdev_lvol.a /src/spdk/build/lib/libspdk_blobfs_bdev.a /src/spdk/build/lib/libspdk_nvmf.a /src/spdk/build/lib/libspdk_event_vhost_blk.a /src/spdk/build/lib/libspdk_bdev_delay.a /src/spdk/build/lib/libspdk_scheduler_dynamic.a /src/spdk/build/lib/libspdk_bdev.a /src/spdk/build/lib/libspdk_init.a /src/spdk/build/lib/libspdk_bdev_ftl.a /src/spdk/build/lib/libspdk_event_nbd.a /src/spdk/build/lib/libspdk_bdev_split.a /src/spdk/build/lib/libspdk_accel.a /src/spdk/build/lib/libspdk_event_vmd.a /src/spdk/build/lib/libspdk_sock_posix.a /src/spdk/build/lib/libspdk_bdev_null.a /src/spdk/build/lib/libspdk_bdev_gpt.a /src/spdk/build/lib/libspdk_dma.a /src/spdk/build/lib/libspdk_scsi.a /src/spdk/build/lib/libspdk_bdev_aio.a /src/spdk/build/lib/libspdk_iscsi.a /src/spdk/build/lib/libspdk_event_vhost_scsi.a /src/spdk/build/lib/libspdk_virtio.a /src/spdk/build/lib/libspdk_ut_mock.a /src/spdk/build/lib/libspdk_env_dpdk.a /src/spdk/build/lib/libspdk_notify.a /src/spdk/build/lib/libspdk_rpc.a /src/spdk/build/lib/libspdk_bdev_virtio.a /src/spdk/build/lib/libspdk_log.a /src/spdk/build/lib/libspdk_lvol.a /src/spdk/build/lib/libspdk_bdev_passthru.a /src/spdk/build/lib/libspdk_bdev_raid.a /src/spdk/build/lib/libspdk_util.a /src/spdk/build/lib/libspdk_blob_bdev.a /src/spdk/build/lib/libspdk_event_bdev.a /src/spdk/build/lib/libspdk_event_iscsi.a /src/spdk/build/lib/libspdk_event_nvmf.a /src/spdk/build/lib/libspdk_blobfs.a /src/spdk/build/lib/libspdk_vmd.a /src/spdk/build/lib/libspdk_conf.a /src/spdk/build/lib/libspdk_thread.a /src/spdk/build/lib/libspdk_trace.a /src/spdk/build/lib/libspdk_env_dpdk_rpc.a /src/spdk/build/lib/libspdk_bdev_error.a /src/spdk/build/lib/libspdk_jsonrpc.a /src/spdk/build/lib/libspdk_scheduler_gscheduler.a /src/spdk/build/lib/libspdk_event_scsi.a /src/spdk/build/lib/libspdk_event_accel.a /src/spdk/build/lib/libspdk_event_sock.a -o $outexe
cp $outexe /out/
done

