# oss-fuzz 

oss-fuzz is an effort to apply coverage-guided software fuzzing on scale to test open source software. It grew out of Chrome in-process fuzzing effort ([Blog Post](https://security.googleblog.com/2016/08/guided-in-process-fuzzing-of-chrome.html), [Project Page](https://chromium.googlesource.com/chromium/src/testing/libfuzzer/)). 


*Project Status*: The project currently is in early stage. We focus on libFuzzer first. Documentation and smoothing the process is our main priority.

## Documentation

* [New Library Guide](docs/new_library.md) walks through steps necessary to add fuzzers to an open source project.
* [Chrome's Efficient Fuzzer Guide](https://chromium.googlesource.com/chromium/src/testing/libfuzzer/+/HEAD/efficient_fuzzer.md) while contains some chrome-specifics, is an excellent documentation on making your fuzzer better.


## References
* [libFuzzer](http://llvm.org/docs/LibFuzzer.html)
* [Chromium In-Process Fuzzing Project Page](https://chromium.googlesource.com/chromium/src/testing/libfuzzer/)

