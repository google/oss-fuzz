# Ideal integration with OSS-Fuzz 
OSS projects have different build and test systems and so we can not expect them
to have a unified way of implementing and maintaining fuzz targets and integrating
them with OSS-Fuzz. However we will still try to give recommendations on the preferred ways. 

## Fuzz Target
The code of the [fuzz target(s)](http://libfuzzer.info/#fuzz-target) should be part of the project's source code repository. 
All fuzz targets should be easily discoverable (e.g. reside in the same directory, or follow the same naming pattern, etc). 

Examples: 
[boringssl](https://github.com/google/boringssl/tree/master/fuzz),
[SQLite](https://www.sqlite.org/src/artifact/ad79e867fb504338),
[s2n](https://github.com/awslabs/s2n/tree/master/tests/fuzz),
[openssl](https://github.com/openssl/openssl/tree/master/fuzz),
[FreeType](http://git.savannah.gnu.org/cgit/freetype/freetype2.git/tree/src/tools/ftfuzzer),
[re2](https://github.com/google/re2/tree/master/re2/fuzzing),
[harfbuzz](https://github.com/behdad/harfbuzz/tree/master/test/fuzzing),
[pcre2](http://vcs.pcre.org/pcre2/code/trunk/src/pcre2_fuzzsupport.c?view=markup),
[ffmpeg](https://github.com/FFmpeg/FFmpeg/blob/master/doc/examples/decoder_targeted.c).


## Seed Corpus
* The seed corpus should be available in revision control (same or different as the source code). 
The seed corpus should be maintained by the project owners and extended every time a bug found by the fuzz target is fixed. 
Inputs that trigger important parts of the code are also welcome.

Examples: 
[boringssl](https://github.com/google/boringssl/tree/master/fuzz),
[openssl](https://github.com/openssl/openssl/tree/master/fuzz),


## Regression Testing
The fuzz targets should be regularly tested (not necessary fuzzed!) as a part
of the project's regression testing process.
One way to do so is to link the fuzz target with a simple driver
(e.g. [this one](https://github.com/llvm-mirror/llvm/tree/master/lib/Fuzzer/standalone))
that runs the provided inputs and use this driver with the seed corpus. 
If possible, use the [sanitizers](https://github.com/google/sanitizers) during regression testing.

Examples: [SQLite](https://www.sqlite.org/src/artifact/d9f1a6f43e7bab45)

## Build support
A plethora of different build systems exist in the open-source world.
And the less OSS-Fuzz knows about them the better it can scale. 

An ideal build integration for OSS-Fuzz would look like this:
* For every fuzz target in the project there is a build rule that builds `foo_fuzzer.a`,
an archive that contains the fuzzing entry point (`LLVMFuzzerTestOneInput`)
and all the code it depends on, but not the `main()` function
* The build system supports changing the compiler and passing extra compiler
flags so that the build command for a `foo_fuzzer.a` looks like this: 
`CC="clang $FUZZER_FLAGS" CXX="clang++ $FUZZER_FLAGS" make_or_whatever_other_command foo_fuzzer.a`.

In this case linking the target with e.g. libFuzzer will look like "clang++ foo_fuzzer.a libFuzzer.a".
This will allow to have minimal OSS-Fuzz-specific configuration and thus be more robust.  
