#!/bin/bash -eu
# Copyright 2022 Google LLC
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

# cpio pkg  
cd $SRC/u-root/pkg/cpio
go mod init cpio
go mod tidy
go install github.com/AdamKorcz/go-118-fuzz-build@latest
go get github.com/AdamKorcz/go-118-fuzz-build/testingtypes
go get github.com/AdamKorcz/go-118-fuzz-build/utils

cp $SRC/u-root/pkg/cpio/testdata/fuzz/*.dict $SRC/u-root/pkg/cpio/testdata/fuzz/*.options $OUT

## FuzzReadWriteNewc
zip -j $OUT/fuzz_read_write_newc_seed_corpus.zip $SRC/u-root/pkg/cpio/testdata/fuzz/corpora/*
compile_native_go_fuzzer $SRC/u-root/pkg/cpio FuzzReadWriteNewc fuzz_read_write_newc

## FuzzWriteReadInMemArchive
compile_native_go_fuzzer $SRC/u-root/pkg/cpio FuzzWriteReadInMemArchive fuzz_write_read_in_mem_archive

# grub pkg  
cd $SRC/u-root/pkg/boot/grub
go mod init grub
go mod tidy
go install github.com/AdamKorcz/go-118-fuzz-build@latest
go get github.com/AdamKorcz/go-118-fuzz-build/testingtypes
go get github.com/AdamKorcz/go-118-fuzz-build/utils

cp $SRC/u-root/pkg/boot/grub/testdata/fuzz/*.dict $SRC/u-root/pkg/boot/grub/testdata/fuzz/*.options $OUT

## FuzzParseEnvFile
compile_native_go_fuzzer $SRC/u-root/pkg/boot/grub FuzzParseEnvFile fuzz_parse_env_file

## FuzzParseGrubConfig
find $SRC/u-root/pkg/boot/grub/testdata_new -name "grub.cfg" -exec zip $OUT/fuzz_parse_grub_config_seed_corpus.zip {} +
compile_native_go_fuzzer $SRC/u-root/pkg/boot/grub FuzzParseGrubConfig fuzz_parse_grub_config

# localboot pkg
cd $SRC/u-root/cmds/boot/localboot
go mod init localboot
go mod tidy
go install github.com/AdamKorcz/go-118-fuzz-build@latest
go get github.com/AdamKorcz/go-118-fuzz-build/testingtypes
go get github.com/AdamKorcz/go-118-fuzz-build/utils

cp $SRC/u-root/pkg/boot/grub/testdata/fuzz/*.dict $SRC/u-root/cmds/boot/localboot/testdata/fuzz/*.options $OUT

## FuzzParseGrubCfg
find $SRC/u-root/pkg/boot/grub/testdata_new -name "grub.cfg" -exec zip $OUT/fuzz_parse_grub_cfg_seed_corpus.zip {} +

compile_native_go_fuzzer $SRC/u-root/cmds/boot/localboot FuzzParseGrubCfg fuzz_parse_grub_cmd_cfg

# syslinux pkg
cd $SRC/u-root/pkg/boot/syslinux
go mod init syslinux
go mod tidy
go install github.com/AdamKorcz/go-118-fuzz-build@latest
go get github.com/AdamKorcz/go-118-fuzz-build/testingtypes
go get github.com/AdamKorcz/go-118-fuzz-build/utils

cp $SRC/u-root/pkg/boot/syslinux/testdata/fuzz/*.dict $SRC/u-root/pkg/boot/syslinux/testdata/fuzz/*.options $OUT

## FuzzParseSyslinuxConfig
find $SRC/u-root/pkg/boot/syslinux/testdata -name "isolinux.cfg" -exec zip $OUT/fuzz_parse_syslinux_config_seed_corpus.zip {} +

compile_native_go_fuzzer $SRC/u-root/pkg/boot/syslinux FuzzParseSyslinuxConfig fuzz_parse_syslinux_config