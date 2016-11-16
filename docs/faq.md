# Frequently Asked Questions

## Why do you use a [different issue tracker](https://bugs.chromium.org/p/oss-fuzz/issues/list) for reporting bugs in fuzz targets?

Security access control is important for the kind of issues that OSS-Fuzz detects.
We will reconsider github issue tracker once there are access control
features available.

## Why do you use Docker?

Building fuzzers requires building your target with a fresh Clang compiler and special compiler flags. 
An easy-to-use Docker image is provided to simplify toolchain distribution. This also limits our exposure
to multitude of Linux varieties and provides a reproducible and (more) secure environment for fuzzer
building and execution.

If you'd like to get more familiar with how libFuzzer-style fuzzers work in
general, check out [this page](http://llvm.org/docs/LibFuzzer.html).
