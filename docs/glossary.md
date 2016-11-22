# OSS-Fuzz Glossary

**WORK-IN-PROGRESS**

Naming things is hard.<BR>
This page tries to reduce confusion around fuzz-related terminology.

## Fuzz Target
Or **Target Function** or **Fuzzing Target Function**, or **Fuzzing Entry Point**.<BR>
A function to which we apply fuzzing.
A [specific signature](http://libfuzzer.info#fuzz-target) must be used for OSS-Fuzz.
Examples: [openssl](https://github.com/openssl/openssl/blob/master/fuzz/x509.c),
[SQLite](https://www.sqlite.org/src/artifact/ad79e867fb504338),
[re2](https://github.com/google/re2/blob/master/re2/fuzzing/re2_fuzzer.cc).

A Fuzz Target can and should also be used for regression testing
and for reproducing bug reports, see [ideal integration](ideal_integration.md).

## Library Configuration
???Any better name??? 

OSS-Fuzz-specific term. <BR>
OSS-Fuzz applies fuzzing to [Fuzz Targets](#fuzz-target)
that test APIs of some specific opensource library
(or sometimes, internal functions of some application). 
One library may have more than one Fuzz Target
(example: [openssl](https://github.com/openssl/openssl/blob/master/fuzz/)),
but OSS-Fuzz will have a single set of configuration files for such library. 
This is what we call **Library Configuration**.

## Fuzzing Engine

A tool that tries to find interesting inputs for a Fuzz Target by executing it.
Examples: [libFuzzer](http://lbfuzzer.info),
[AFL](lcamtuf.coredump.cx/afl/),
[honggfuzz](https://github.com/google/honggfuzz), etc 

See also [Mutation Engine](#mutation-engine) and [Test Generator](#test-generator).

## Fuzzer build

A binary built for a [fuzz target](#fuzz-target) with (or for) a specific [fuzzing engine](#fuzzing-engine),
in a specific build mode (e.g. with enabled or disabled assertions), 
optionally combined with a [sanitizer](#sanitizer).


## Test Input
A sequence of bytes that is used as the input to a Fuzz Target. 
Typicaly, a test input is stored in a separate file. 

## Reproducer 
Or a **testcase**.<BR> 
A [Test Input](#test-input) that causes a specific bug to reproduce. 

## Corpus
Or **test corpus**, or **fuzzing corpus**. 
A set of [test inputs](#test-input).

## Mutation Engine
A tool that take a set of testcases
and creates their mutations, but do not directly feed the mutations to Fuzz Targets.
Example: [Radamsa](https://github.com/aoh/radamsa),

## Test Generator
A tool that generates testcases according to some rules or grammar. 
Example: [csmith](https://embed.cs.utah.edu/csmith/) (a test generator for the C language).

## Sanitizer
A dynamic testing tool that can detect bugs during program execution.
An incomplete list:
[ASan](http://clang.llvm.org/docs/AddressSanitizer.html),
[MSan](http://clang.llvm.org/docs/MemorySanitizer.html),
[TSan](http://clang.llvm.org/docs/ThreadSanitizer.html),
[LSan](http://clang.llvm.org/docs/LeakSanitizer.html),
[UBSan](http://clang.llvm.org/docs/UndefinedBehaviorSanitizer.html). 

## Fuzzer

The most overloaded term, which makes it bad (maybe, we should try avoiding it?).
Sometimes the "Fuzzer" is referred to a [fuzz target](#fuzz-target),
sometimes to a [fuzzing engine](#fuzzing-engine),
[mutation engine](#mutation-engine),
or a [test generator](#test-generator). 
sometimes to a [fuzzer build](#fuzzer-build).

