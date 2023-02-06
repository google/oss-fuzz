---
layout: default
title: Fuzz Introspector
parent: Advanced topics
nav_order: 2
permalink: /advanced-topics/fuzz-introspector/
---

# Fuzz Introspector
{: .no_toc}

For projects written in C/C++, Python and Java you can generate Fuzz
Introspector reports to help guide the development of your fuzzing suite.
These reports help to extract details about the fuzzing setup of your
project with the goal of making it easier to improve the fuzzing set up.
The Fuzz Introspector reports are generated automatically and uploaded
to the cloud like code coverage reports, and you can also generate them
locally using the OSS-Fuzz helper script.


- TOC
{:toc}
---

## Fuzz Introspector overview

As soon as your project is run with ClusterFuzz (<1 day), you can view the Fuzz
Introspector report for your project.
[Fuzz Introspector](https://github.com/ossf/fuzz-introspector) helps you
understand your fuzzers' performance and identify any potential blockers.
It provides individual and aggregated fuzzer reachability and coverage reports.
You can monitor each fuzzer's static reachability potential and compare it
against dynamic coverage and identify any potential bottlenecks.
Fuzz Introspector can offer suggestions on increasing coverage by adding new
fuzz targets or modify existing ones.
Fuzz Introspector reports can be viewed from the [OSS-Fuzz
homepage](https://oss-fuzz.com/) or through this
[index](http://oss-fuzz-introspector.storage.googleapis.com/index.html).

- [Fuzz Introspector documentation](https://fuzz-introspector.readthedocs.io/en/latest/)
- [Fuzz Introspector source code](https://github.com/ossf/fuzz-introspector)
- [OSS-Fuzz Fuzz Introspector reports](http://oss-fuzz-introspector.storage.googleapis.com/index.html)


## Tutorials and guides

The reports generated can be a lot to digest when first viewing them. The 
[Fuzz Introspector documentation](https://fuzz-introspector.readthedocs.io/en/latest/)
provides various user guides and tutorials rooted in OSS-Fuzz projects, which is
a useful reference on how to make use of the reports.

For ideas on how to use Fuzz Introspector, see [user guides](https://fuzz-introspector.readthedocs.io/en/latest/user-guides/index.html) which includes sections e.g.
- [Quickly extract overview of a given project](https://fuzz-introspector.readthedocs.io/en/latest/user-guides/quick-overview.html)
- [Get ideas for new fuzz targets](https://fuzz-introspector.readthedocs.io/en/latest/user-guides/get-ideas-for-new-targets.html)
- [Comparing introspector reports](https://fuzz-introspector.readthedocs.io/en/latest/user-guides/comparing-introspector-reports.html)

## Run Fuzz Introspector locally

To generate a Fuzz Introspector report locally use `infra/helper.py` and the
`introspector` command. Fuzz Introspector relies on code coverage to
analyze a given project, and this means we need to extract code coverage in the
Fuzz Introspector process. We can do this in two ways. First, by running the fuzzers
for a given amount of time, and, second, by generating code coverage using the public
corpus available from OSS-Fuzz.


### Generate reports by running fuzzers for X seconds

The following command will generate a Fuzz Introspector report for the `libdwarf` project
and will extract code coverage based on a corpus created from running the fuzzers for 30
seconds.

```bash
$ python3 infra/helper.py introspector libdwarf --seconds=30
```

If the above command was succesful, you should see output along the lines of:

```bash
INFO:root:To browse the report, run: python3 -m http.server 8008 --directory /home/my_user/oss-fuzz/build/out/libdwarf/introspector-report/inspector and navigate to localhost:8008/fuzz_report.html in your browser
```
The above output gives you directions on how to start a simple webserver using
`python3 -m http.server`, which you can use to view the Fuzz Introspector report.

### Generate reports by using public corpora

The following command will generate a Fuzz Introspector report for the `libdwarf` project
and will extract code coverage based on a corpus created from running the fuzzers for 30
seconds.

```bash
$ python3 infra/helper.py introspector libdwarf --public-corpora
```

Assuming the above command is succesful you can view the report using `python3 -m http.server`
following the example described above.


## Differences in build tooling

There are some differences in build environment for Fuzz Introspector builds
in comparison to e.g. ASAN or code coverage builds. The reason is that
Fuzz Introspector relies on certain compile-time tools to do its analysis.
This compile time tooling differs between languages, namely:
- For C/C++, Fuzz Introspector relies on [LLVM LTO](https://llvm.org/docs/LinkTimeOptimization.html) and [LLVM Gold](https://llvm.org/docs/GoldPlugin.html)
- For Python, Fuzz Introspector relies on a modified [PyCG](https://github.com/vitsalis/PyCG)
- For Java, Fuzz Introspector relies on [Soot](https://soot-oss.github.io/soot/)

The consequence of this is your project must be compatible with these projects.
PyCG and Soot have not shown to be a blocker for many projects, however, experience
has shown that sometimes a project's build needs modification in order to compile
with LLVM LTO. The easiest way to test if your project works with LLVM is checking
whether your project can compile with the flags `-flto -fuse-ld=gold` and using
the gold linker. OSS-Fuzz automatically sets these flags and linker options when
using `infra/helper.py` to build your project with `--sanitizer=introspector`, e.g.

```bash
python3 infra/helper.py build_fuzzers --sanitizer=introspector PROJ_NAME
```
