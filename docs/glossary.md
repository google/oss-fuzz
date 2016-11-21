# Fuzzing Glossary

TODO

Naming things is hard. This page tries to reduce confusion around naming.

## Fuzz Target
Or **Target Function** or **Fuzzing Target Function**.<BR>
A function to which we apply fuzzing.
A [specific signature](libfuzzer.info#fuzz-target) must be used for OSS-Fuzz.
Examples: [openssl](https://github.com/openssl/openssl/blob/master/fuzz/x509.c),
[SQLite](https://www.sqlite.org/src/artifact/ad79e867fb504338),
[e2](https://github.com/google/re2/blob/master/re2/fuzzing/re2_fuzzer.cc).
A Fuzz Target can and should also be used for regression testing
and for reproducing bug reports, see [ideal integration](ideal_integration.md).

## Fuzzing Engine

A program that tries to find interesting inputs for a Fuzz Target by executing it.
Examples: [libFuzzer](http://lbfuzzer.info),
[AFL](lcamtuf.coredump.cx/afl/),
[honggfuzz](https://github.com/google/honggfuzz), etc 

See also [#mutation-engine] and [#test-generator].

## Test Input
Or **reproducer**, or **testcase**. 
A sequence of bytes that is used as the input to a Fuzz Target. 

## Mutation Engine
A tool that take a set of testcases
and creates their mutations, but do not directly feed the mutations to Fuzz Targets.
Example [Radamsa](https://github.com/aoh/radamsa),

## Test Generator
A tool that generates testcases 

## Fuzzer

The most overloaded term, which makes it bad (maybe, we should try avoiding it?).
Sometimes the "Fuzzer" is referred to a Fuzz Target, sometimes to a Fuzzing Engine, Mutation Engine, or a Test Generator. 
Sometimes to a binary built from a Fuzz Target using some of the Fuzzing Engine and optionally with some dynamic testing tool. 

