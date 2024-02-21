# OSS-Fuzz VSCode extension

[OSS-Fuzz](https://github.com/google/oss-fuzz) is a fuzzing toolkit and service for fuzzing open source projects. This VSCode extension provides features and capabilities for interacting with the OSS-Fuzz toolkit and also to compare local changes to the OSS-Fuzz cloud database by way of [Open source fuzz introspection](https://introspector.oss-fuzz.com).

## Features

The VSCode extension is largely driven by commands at this point. The featues of these commands includes:

- Easily setting up OSS-Fuzz
- Templates for easily setting up a new OSS-Fuzz project
- Building arbitrary projects from OSS-Fuzz
- Modify a project from VSCode and test changes in OSS-Fuzz
- Easily extract code coverage of fuzzers, including local-only fuzzers
- Compare local code coverage to what is currently achieved by OSS-Fuzz
- Auto-generation of fuzzer templates

For a full list of commands and their features, please check the commands page.