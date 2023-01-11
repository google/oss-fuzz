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
printf "package cpio\nimport _ \"github.com/AdamKorcz/go-118-fuzz-build/testing\"\n" > registerfuzzdep.go
go mod tidy

cp $SRC/u-root/pkg/cpio/testdata/fuzz/*.dict $SRC/u-root/pkg/cpio/testdata/fuzz/*.options $OUT

## FuzzReadWriteNewc
zip -j $OUT/fuzz_read_write_newc_seed_corpus.zip $SRC/u-root/pkg/cpio/testdata/fuzz/corpora/*
compile_native_go_fuzzer $SRC/u-root/pkg/cpio FuzzReadWriteNewc fuzz_read_write_newc

## FuzzWriteReadInMemArchive
compile_native_go_fuzzer $SRC/u-root/pkg/cpio FuzzWriteReadInMemArchive fuzz_write_read_in_mem_archive

# grub pkg  
cd $SRC/u-root/pkg/boot/grub
go mod init grub
printf "package grub\nimport _ \"github.com/AdamKorcz/go-118-fuzz-build/testing\"\n" > registerfuzzdep.go
go mod tidy

cp $SRC/u-root/pkg/boot/grub/testdata/fuzz/*.dict $SRC/u-root/pkg/boot/grub/testdata/fuzz/*.options $OUT

## FuzzParseEnvFile
compile_native_go_fuzzer $SRC/u-root/pkg/boot/grub FuzzParseEnvFile fuzz_parse_env_file

## FuzzParseGrubConfig
find $SRC/u-root/pkg/boot/grub/testdata_new -name "grub.cfg" -exec zip $OUT/fuzz_parse_grub_config_seed_corpus.zip {} +
compile_native_go_fuzzer $SRC/u-root/pkg/boot/grub FuzzParseGrubConfig fuzz_parse_grub_config

# localboot pkg
cd $SRC/u-root/cmds/boot/localboot
go mod init localboot
printf "package main\nimport _ \"github.com/AdamKorcz/go-118-fuzz-build/testing\"\n" > registerfuzzdep.go
go mod tidy

cp $SRC/u-root/pkg/boot/grub/testdata/fuzz/*.dict $SRC/u-root/cmds/boot/localboot/testdata/fuzz/*.options $OUT

## FuzzParseGrubCfg
find $SRC/u-root/pkg/boot/grub/testdata_new -name "grub.cfg" -exec zip $OUT/fuzz_parse_grub_cfg_seed_corpus.zip {} +
compile_native_go_fuzzer $SRC/u-root/cmds/boot/localboot FuzzParseGrubCfg fuzz_parse_grub_cmd_cfg

# syslinux pkg
cd $SRC/u-root/pkg/boot/syslinux
go mod init syslinux
printf "package syslinux\nimport _ \"github.com/AdamKorcz/go-118-fuzz-build/testing\"\n" > registerfuzzdep.go
go mod tidy

cp $SRC/u-root/pkg/boot/syslinux/testdata/fuzz/*.dict $SRC/u-root/pkg/boot/syslinux/testdata/fuzz/*.options $OUT

## FuzzParseSyslinuxConfig
find $SRC/u-root/pkg/boot/syslinux/testdata -name "isolinux.cfg" -exec zip $OUT/fuzz_parse_syslinux_config_seed_corpus.zip {} +
compile_native_go_fuzzer $SRC/u-root/pkg/boot/syslinux FuzzParseSyslinuxConfig fuzz_parse_syslinux_config

# gosh cmd
cd $SRC/u-root/cmds/core/gosh
go mod init gosh
go get github.com/u-root/prompt@v0.0.0-20221110083427-a2ad3c8339a8
printf "package main\nimport _ \"github.com/AdamKorcz/go-118-fuzz-build/testing\"\n" > registerfuzzdep.go
go mod tidy

cp $SRC/u-root/cmds/core/gosh/testdata/fuzz/*.dict $SRC/u-root/cmds/core/gosh/testdata/fuzz/*.options $OUT

## FuzzRun
find $SRC/u-root/cmds/core/gosh/testdata/fuzz/corpora -name "*.seed" -exec zip $OUT/fuzz_gosh_run_seed_corpus.zip {} +
compile_native_go_fuzzer $SRC/u-root/cmds/core/gosh FuzzRun fuzz_gosh_run

# esxi pkg
cd $SRC/u-root/pkg/boot/esxi
go mod init esxi
printf "package esxi\nimport _ \"github.com/AdamKorcz/go-118-fuzz-build/testing\"\n" > registerfuzzdep.go
go mod tidy
cp $SRC/u-root/pkg/boot/esxi/testdata/fuzz/*.dict $SRC/u-root/pkg/boot/esxi/testdata/fuzz/*.options $OUT

## FuzzParse
find $SRC/u-root/pkg/boot/esxi/testdata -name "*.cfg" -exec zip $OUT/fuzz_esxi_parse_seed_corpus.zip {} +
compile_native_go_fuzzer $SRC/u-root/pkg/boot/esxi FuzzParse fuzz_esxi_parse

# ipxe pkg
cd $SRC/u-root/pkg/boot/netboot/ipxe
go mod init ipxe
printf "package ipxe\nimport _ \"github.com/AdamKorcz/go-118-fuzz-build/testing\"\n" > registerfuzzdep.go

sed 's/log\: ulogtest\.Logger/\/\/log\: ulogtest\.Logger/g' -i $SRC/u-root/pkg/boot/netboot/ipxe/fuzz_test.go
sed 's/c\.log\.Printf/\/\/c\.log\.Printf/g' -i $SRC/u-root/pkg/boot/netboot/ipxe/ipxe.go
sed 's/"github\.com\/u-root\/u-root\/pkg\/ulog\/ulogtest/\/\/"github.com\/u-root\/u-root\/pkg\/ulog\/ulogtest/g' -i $SRC/u-root/pkg/boot/netboot/ipxe/fuzz_test.go

go mod tidy

cp $SRC/u-root/pkg/boot/netboot/ipxe/testdata/fuzz/*.dict $SRC/u-root/pkg/boot/netboot/ipxe/testdata/fuzz/*.options $OUT

## FuzzParseIpxeConfig
find $SRC/u-root/pkg/boot/netboot/ipxe/testdata/fuzz/corpora -name "*.seed" -exec zip $OUT/fuzz_ipxe_parse_config_seed_corpus.zip {} +
compile_native_go_fuzzer $SRC/u-root/pkg/boot/netboot/ipxe FuzzParseIpxeConfig fuzz_ipxe_parse_config

# smbios pkg
cd $SRC/u-root/pkg/smbios
go mod init smbios
printf "package smbios\nimport _ \"github.com/AdamKorcz/go-118-fuzz-build/testing\"\n" > registerfuzzdep.go
go mod tidy
cp $SRC/u-root/pkg/smbios/testdata/fuzz/*.dict $SRC/u-root/pkg/smbios/testdata/fuzz/*.options $OUT

## FuzzParseInfo
find $SRC/u-root/pkg/smbios/testdata -name "*.bin" -exec zip $OUT/fuzz_smbios_parse_info_seed_corpus.zip {} +
compile_native_go_fuzzer $SRC/u-root/pkg/smbios FuzzParseInfo fuzz_smbios_parse_info

# ip cmd
cd $SRC/u-root/cmds/core/ip
go mod init ip
printf "package main\nimport _ \"github.com/AdamKorcz/go-118-fuzz-build/testing\"\n" > registerfuzzdep.go
go mod tidy
cp $SRC/u-root/cmds/core/ip/testdata/fuzz/*.dict $SRC/u-root/cmds/core/ip/testdata/fuzz/*.options $OUT

## FuzzIPCmd
find $SRC/u-root/cmds/core/ip/testdata/fuzz/corpora -name "*.seed" -exec zip $OUT/fuzz_ip_cmd_seed_corpus.zip {} +
compile_native_go_fuzzer $SRC/u-root/cmds/core/ip FuzzIPCmd fuzz_ip_cmd