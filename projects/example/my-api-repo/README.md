Example of [OSS-Fuzz ideal integration](https://google.github.io/oss-fuzz/advanced-topics/ideal-integration/).

This directory contains an example software project that has most of the traits of [ideal](https://google.github.io/oss-fuzz/advanced-topics/ideal-integration/) support for fuzzing. 

## Files in my-api-repo
Imagine that these files reside in your project's repository:

* [my_api.h](my_api.h): and [my_api.cpp](my_api.cpp) implement the API we want to test/fuzz. The function `DoStuff()` inside [my_api.cpp](my_api.cpp) contains a bug. (Find it!)
* [do_stuff_unittest.cpp](do_stuff_unittest.cpp): is a unit test for `DoStuff()`. Unit tests are not necessary for fuzzing but are generally a good practice.
* [do_stuff_fuzzer.cpp](do_stuff_fuzzer.cpp): is a [fuzz target](https://llvm.org/docs/LibFuzzer.html#fuzz-target) for `DoStuff()`.
* [do_stuff_test_data](do_stuff_test_data): corpus directory for [do_stuff_fuzzer.cpp](do_stuff_fuzzer.cpp).
* [do_stuff_fuzzer.dict](do_stuff_fuzzer.dict): a [fuzzing dictionary file](https://google.github.io/oss-fuzz/getting-started/new-project-guide#dictionaries) for `DoStuff()`. Optional, but may improve fuzzing in many cases. 
* [Makefile](Makefile): is a build file (the same can be done with other build systems):
  * accepts external compiler flags via `$CC`, `$CXX`, `$CFLAGS`, `$CXXFLAGS`
  * accepts external fuzzing engine via `$LIB_FUZZING_ENGINE`, by default uses [standalone_fuzz_target_runner.cpp](standalone_fuzz_target_runner.cpp)
  * builds the fuzz target(s) and their corpus archive(s)
  * `make check` executes [do_stuff_fuzzer.cpp](do_stuff_fuzzer.cpp) on [`do_stuff_test_data/*`](do_stuff_test_data), thus ensures that the fuzz target is up to date and uses it as a regression test.
* [standalone_fuzz_target_runner.cpp](standalone_fuzz_target_runner.cpp): is a simple standalone runner for fuzz targets. You may use it to execute a fuzz target on given files w/o having to link in libFuzzer or other fuzzing engine.

## Files in OSS-Fuzz repository
* [oss-fuzz/projects/example](..)
  * [Dockerfile](../Dockerfile): sets up the build environment
  * [build.sh](../build.sh): builds the fuzz target(s). The smaller this file the better (most of the logic should be inside the project's build system).
  * [project.yaml](../project.yaml): short project description and contact info.

## Example bug
Example bug report filed automatically: https://bugs.chromium.org/p/oss-fuzz/issues/detail?id=1562


