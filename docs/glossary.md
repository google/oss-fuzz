# Fuzzing Gloassary

TODO

Naming things is hard. This page tries to reduce confusion around naming.

## Fuzz Target**
Or **Target Function** or **Fuzzing Target Function**.<BR>
A function to which we apply fuzzing.
A [specific signature](libfuzzer.info#fuzz-target) must be used for OSS-Fuzz.
Examples: [openssl](https://github.com/openssl/openssl/blob/master/fuzz/x509.c),
[SQLite](https://www.sqlite.org/src/artifact/ad79e867fb504338),
[e2](https://github.com/google/re2/blob/master/re2/fuzzing/re2_fuzzer.cc).
A Fuzz Target can and should also be used for regression testing
and for reproducing bug reports, see [ideal integration](ideal_integration.md).

* **Fuzzing Engine** a program that tries to find interesting inputs 
