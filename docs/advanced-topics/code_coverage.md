---
layout: default
title: Code coverage
parent: Advanced topics
nav_order: 2
permalink: /advanced-topics/code-coverage/
---

# Code Coverage
{: .no_toc}

For projects written in C/C++, Rust, Go, Swift or Java and other JVM-based languages,
you can generate code coverage reports using Clang source-based code coverage.
This page walks you through the basic steps.
For more details on C/C++ coverage, see [Clang's documentation].

Code coverage reports generation for other languages is not supported yet.

- TOC
{:toc}
---

## Pull the latest Docker images

Docker images get regularly updated with a newer version of build tools, build
configurations, scripts, and other changes. We recommend you pull the most
recent images by running the following command:

```bash
$ python infra/helper.py pull_images
```

## Build fuzz targets

Code coverage report generation requires a special build configuration to be
used. To create a code coverage build for your project, run these commands:

```bash
$ python infra/helper.py build_image $PROJECT_NAME
$ python infra/helper.py build_fuzzers --sanitizer=coverage $PROJECT_NAME
```

## Establish access to GCS

To get a good understanding of fuzz testing quality, you should generate code
coverage reports by running fuzz targets against the corpus
aggregated by OSS-Fuzz. Set up `gsutil` and ensure that you have access to the
corpora by doing the following:

* Install the [gsutil tool].
* Check whether you have access to the corpus for your project:

```bash
$ gsutil ls gs://${PROJECT_NAME}-corpus.clusterfuzz-external.appspot.com/
```

If you see an authorization error from the command above, run this:

```bash
$ gcloud auth login
```

and try again. Once `gsutil` works, you can run the report generation.

## Generate code coverage reports

### Full project report

If you want to generate a code coverage report using the corpus aggregated on
OSS-Fuzz, run this command:

```bash
$ python infra/helper.py coverage $PROJECT_NAME
```

If you want to generate a code coverage report using the corpus you have
locally, copy the corpus into the
`build/corpus/$PROJECT_NAME/<fuzz_target_name>/` directories for each fuzz
target, then run this command:

```bash
$ python infra/helper.py coverage --no-corpus-download $PROJECT_NAME
```

### Single fuzz target

You can generate a code coverage report for a particular fuzz target by using
the `--fuzz-target` argument:

```bash
$ python infra/helper.py coverage --fuzz-target=<fuzz_target_name> $PROJECT_NAME
```

In this mode, you can specify an arbitrary corpus location for the fuzz target
(instead of the corpus downloaded from OSS-Fuzz) by using `--corpus-dir`:

```bash
$ python infra/helper.py coverage --fuzz-target=<fuzz_target_name> \
    --corpus-dir=<my_local_corpus_dir> $PROJECT_NAME
```

### Additional arguments for `llvm-cov` (C/C++ only)

You may want to use some of the options provided by the [llvm-cov tool], like
`-ignore-filename-regex=`. You can pass these to the helper script after `--`:

```bash
$ python infra/helper.py coverage $PROJECT_NAME -- \
    -ignore-filename-regex=.*code/to/be/ignored/.* <other_extra_args>
```

If you want to specify particular source files or directories to show in the
report, list their paths at the end of the extra arguments sequence:

```bash
$ python infra/helper.py coverage zlib -- \
    <other_extra_args> /src/zlib/inftrees.c /src/zlib_uncompress_fuzzer.cc /src/zlib/zutil.c
```

If you want OSS-Fuzz to use extra arguments when generating code coverage
reports for your project, add the arguments into your `project.yaml` file as
follows:

```yaml
coverage_extra_args: -ignore-filename-regex=.*crc.* -ignore-filename-regex=.*adler.* <other_extra_args>
```

[Clang's documentation]: https://clang.llvm.org/docs/SourceBasedCodeCoverage.html
[gsutil tool]: https://cloud.google.com/storage/docs/gsutil_install
[llvm-cov tool]: https://llvm.org/docs/CommandGuide/llvm-cov.html
