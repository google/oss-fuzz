Example of [OSS-Fuzz ideal integration](../../../docs/ideal_integration.md).

This directory contains a example software project that has all the trais of [ideal](../../../docs/ideal_integration.md) support for fuzzing. 

* [my_api.h](my_api.h) and [my_api.cpp](my_api.cpp) implement the API that we want to test/fuzz. The function `DoStuff()` inside [my_api.cpp](my_api.cpp) contains a bug. (Find it!)
* [do_stuff_unittest.cpp](do_stuff_unittest.cpp) is a unit test for `DoStuff()`. 
* [do_stuff_fuzzer.cpp](do_stuff_fuzzer.cpp) is a [fuzz target](http://libfuzzer.info/#fuzz-target) for `DoStuff()`.
* [standalone_fuzz_taget_runner.cpp](standalone_fuzz_taget_runner.cpp) is a simple standalone runnner for fuzz targets. You may use it to execute a fuzz target on given files w/o having to link in libFuzzer or other fuzzing engine. 
* [do_stuff_test_data](do_stuff_test_data) corpus directory for [do_stuff_fuzzer.cpp](do_stuff_fuzzer.cpp). 
* [Makefile](Makefile) is a build file:
  * accepts external compiler flags via `$CC`, `$CXX`, `$CFLAGS`, `$CXXFLAGS`
  * accepts external fuzzing engine via `$LIB_FUZZING_ENGINE`, by default uses [standalone_fuzz_taget_runner.cpp](standalone_fuzz_taget_runner.cpp)
  * builds the fuzz target(s) and their corpus archive(s)
  * `make check` executes [do_stuff_fuzzer.cpp](do_stuff_fuzzer.cpp) on [`do_stuff_test_data/*`](do_stuff_test_data)


Example bug report filed automatically: https://bugs.chromium.org/p/oss-fuzz/issues/detail?id=1562
