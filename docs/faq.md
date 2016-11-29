# Frequently Asked Questions

## Why do you use a [different issue tracker](https://bugs.chromium.org/p/oss-fuzz/issues/list) for reporting bugs in OSS projects?

Security access control is important for the kind of issues that OSS-Fuzz detects.
We will reconsider github issue tracker once the
[access control feature](https://github.com/isaacs/github/issues/37) is available.

## Why do you use Docker?

Building fuzzers requires building your project with a fresh Clang compiler and special compiler flags. 
An easy-to-use Docker image is provided to simplify toolchain distribution. This also limits our exposure
to a multitude of Linux varieties and provides a reproducible and secure environment for fuzzer
building and execution.
