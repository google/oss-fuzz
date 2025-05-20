#!/bin/bash -eo pipefail
# 使用 OSS-Fuzz 环境变量中的编译器和选项
$CXX $CXXFLAGS buggy.c fuzz_target.cpp -o example-buggy_fuzzer
# 把生成的 fuzz 二进制放到输出目录，helper.py 会把 /out 挂载到宿主机 build/out
cp example-buggy_fuzzer $OUT/

