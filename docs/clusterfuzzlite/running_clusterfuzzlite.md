---
layout: default
parent: ClusterFuzzLite
title: Running ClusterFuzzLite
has_children: true
nav_order: 3
permalink: /clusterfuzzlite/running-clusterfuzzlite/
---
# Running ClusterFuzzLite
{: .no_toc}

- TOC
{:toc}
---

## Overview
TODO: add a diagram.

Once your project's fuzzers can be built and run by the helper script, it is
ready to be fuzzed by ClusterFuzzLite.
The exact method for doing this will depend on the how you are running
ClusterFuzzLite. For guides on how to run ClusterFuzzLite in your particular
environment (e.g. GitHub Actions) see the subguides.
The rest of this page will explain concepts configuration options and that are
agnostic to how ClusterFuzzLite is being run.

## ClusterFuzzLite Tasks

ClusterFuzzLite has the concept of tasks which instruct ClusterFuzzLite what to
do when running.

### Code Review Fuzzing

TODO(metzman): Work on a generic name for CIFuzz/PR fuzzing.

One of the core ways for ClusterFuzzLite to be used is for fuzzing code that is
in review that was just commited.
This use-case is important because it allows ClusterFuzzLite to find bugs before
they are commited into your code and while they are easiest to fix.
To use Code Review Fuzzing, set the configuration option `clusterfuzzlite-task`
to `code-review`.
If you are familiar with OSS-Fuzz's CIFuzz, this task is similar to CIFuzz.
Running other ClusterFuzzLite tasks enhances ClusterFuzzLite's ability to do
Code Review Fuzzing.

If [Batch Fuzzing] is enabled, Code Review Fuzzing will report only newly
introduced bugs and use the corpus developed during batch fuzzing.
If [Code Coverage Reporting] is enabled, Code Review Fuzzing will try to only
run the fuzzers affected by the code change.

### Batch Fuzzing

ClusterFuzzLite can also run in a batch fuzzing mode where all fuzzers are run
for a long amount of time. Unlike Code Review Fuzzing, this task is not meant to
be interactive, it is meant to be long-lasting and generally is more similar to
fuzzing in ClusterFuzz than Code Review Fuzzing. Batch Fuzzing allows
ClusterFuzzLite to build up a corpus for each of your fuzz targets. This corpus
will be used in Code Coverage Reporting as well as Code Review Fuzzing.

### Corpus Prune

If multiple Batch Fuzzing tasks are run concurrently then we strongly recommend
running a pruning task as well. This task is run according to some set schedule
(once a day is probably sufficient) to prune the corpus of redundant testcases,
which can happen if multiple Batch Fuzzing jobs are done concurrently.

### Code Coverage Report

The last task ClusterFuzzLite offers is Code Coverage Reports. This task will
run your fuzzers on the corpus developed during Batch Fuzzing and will generate
an HTML report that shows you which part of your code is covered by batch
fuzzing.

## Configuration Options

Below are some configuration options that you can set when running
ClusterFuzzLite.
We will explain how to set these in each of the subguides.

`language`: (optional) The language your target program is written in. Defaults
to `c++`. This should be the same as the value you set in `project.yaml`. See
[this explanation]({{ site.baseurl }}//getting-started/new-project-guide/#language)
for more details.

`fuzz-time`: Determines how long ClusterFuzzLite spends fuzzing your project in
seconds. The default is 600 seconds.

`sanitizer`: Determines a sanitizer to build and run fuzz targets with. The
choices are `'address'`, and `'undefined'`. The default is `'address'`.

`task`: The task for ClusterFuzzLite to execute. `code-review`
by default. See [ClusterFuzzLite Tasks] for more details on how to run different
tasks.
TODO(metzman): change run_fuzzers_mode to this.

`dry-run`: Determines if ClusterFuzzLite surfaces bugs/crashes. The default
value is `false`. When set to `true`, ClusterFuzzLite will never report a
failure even if it finds a crash in your project. This requires the user to
manually check the logs for detected bugs.

TODO(metzman): We probably want a TOC on this page for subguides.
