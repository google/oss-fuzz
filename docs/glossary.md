# Glossary

Naming things is hard. This page tries to reduce confusion around fuzz-related terminologies.

## Corpus
Or **test corpus**, or **fuzzing corpus**.<BR>
A set of [test inputs](#test-input). In usual context, it is also referred to a set of minimal test inputs that generate maximal code coverage.

## Fuzz Target
Or **Target Function**, or **Fuzzing Target Function**, or **Fuzzing Entry Point**.<BR>
A function to which we apply fuzzing. A [specific signature](http://libfuzzer.info#fuzz-target) is needed for OSS-Fuzz.
Examples: [openssl](https://github.com/openssl/openssl/blob/master/fuzz/x509.c),
[re2](https://github.com/google/re2/blob/master/re2/fuzzing/re2_fuzzer.cc),
[SQLite](https://www.sqlite.org/src/artifact/ad79e867fb504338).

A fuzz target can be used to [reproduce bug reports](reproducing.md). 
It is recommended to use it for regression testing (see [ideal integration](ideal_integration.md)).

## Fuzzer

The most overloaded term and used in a variety of contexts, which makes it bad.
Sometimes, "Fuzzer" is referred to a [fuzz target](#fuzz-target),
sometimes to a [fuzzing engine](#fuzzing-engine),
a [mutation engine](#mutation-engine),
a [test generator](#test-generator) or 
a [fuzzer build](#job-type).

## Fuzzing Engine

A tool that tries to find interesting inputs for a [fuzz target](#fuzz-target) by executing it.
Examples: [libFuzzer](http://lbfuzzer.info),
[AFL](lcamtuf.coredump.cx/afl/),
[honggfuzz](https://github.com/google/honggfuzz), etc 

See also [Mutation Engine](#mutation-engine) and [Test Generator](#test-generator).

## Job type

Or **Fuzzer Build**.<BR>
A [ClusterFuzz](clusterfuzz.md) specific term.
This refers to a build that contains all the [fuzz targets](#fuzz-target) for a given [project](#project)
with a specific [fuzzing engine](#fuzzing-engine), in a specific build mode (e.g. with enabled or disabled assertions), 
and optionally combined with a [sanitizer](#sanitizer).

For example, we have a "libfuzzer_asan_sqlite" job type, indicating a build of all sqlite3 [fuzz targets](#fuzz-target) using 
[libFuzzer](http://lbfuzzer.info) and [ASan](http://clang.llvm.org/docs/AddressSanitizer.html).


## Mutation Engine
A tool that take a set of testcases as input and creates their mutated versions. 
It does not feed the mutations to [fuzz target](#fuzz-target).
Example: [radamsa](https://github.com/aoh/radamsa) (a generic test mutator).

## Project

An entity comprising of various [fuzz targets](#fuzz-target)
that test APIs (or internal functions) of a specific open source project.
Each project has a single set of configuration files and may have more than one [fuzz target](#fuzz-target)
(example: [openssl](https://github.com/openssl/openssl/blob/master/fuzz/)). 

## Reproducer 
Or a **testcase**.<BR>
A [test input](#test-input) that causes a specific bug to reproduce. 

## [Sanitizer](https://github.com/google/sanitizers)
A [dynamic testing](https://en.wikipedia.org/wiki/Dynamic_testing) tool that can detect bugs during program execution.
Examples:
[ASan](http://clang.llvm.org/docs/AddressSanitizer.html),
[DFSan](http://clang.llvm.org/docs/DataFlowSanitizer.html),
[LSan](http://clang.llvm.org/docs/LeakSanitizer.html),
[MSan](http://clang.llvm.org/docs/MemorySanitizer.html),
[TSan](http://clang.llvm.org/docs/ThreadSanitizer.html),
[UBSan](http://clang.llvm.org/docs/UndefinedBehaviorSanitizer.html). 

## Test Generator
A tool that generates testcases from scratch according to some rules or grammar. 
Examples: 
[csmith](https://embed.cs.utah.edu/csmith/) (a test generator for C language),
[cross_fuzz](http://lcamtuf.coredump.cx/cross_fuzz/) (a cross-document DOM binding test generator).

## Test Input
A sequence of bytes that is used as the input to a [fuzz target](#fuzz-target). 
Typicaly, a test input is stored in a separate file. 
