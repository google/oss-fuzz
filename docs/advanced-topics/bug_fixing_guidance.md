---
layout: default
title: Bug fixing guidance
nav_order: 6
permalink: /advanced-topics/bug-fixing-guidance
---

# Bug fixing guidance
{: .no_toc}

This page provides brief guidance on how to prioritise and fix bugs reported by
OSS-Fuzz.

- TOC
{:toc}

## Threat modelling
In general the severity of an issue reported by OSS-Fuzz must be determined
relative to the threat model of the project under analysis. Therefore, although
the fuzzers OSS-Fuzz makes an effort into determining the severity of the bug
the true severity of the bug depends on the threat model of the project.

## Bug prioritisation

### Security issues
These are the top priority of solving. A label is attached to these on
the OSS-Fuzz testcase page and you can also search up all of these on monorail
using the search pattern `-Bug=security`.

Issues of this kind include issues reported by Address Sanitizer, e.g.
heap-based buffer overflows, stack-based buffer overflows and use-after-frees.

### Functional issues and memory leaks
These are issues that in general can tamper with the functionality of the
application. The bugs that have highest priority in this case are those that
can be easily triggered by an untrusted user of the project.

### Timeouts and out-of-memory
These are in general the least prioritised issues to solve.

### Bug prioritisation of non C/C++ projects
Currently there is no prioritisation of bugs in non C/C++ projects. As such, in
this scenario it is crucial you do the analysis yourself relative to the threat
model of your project.

## Non-reproducible bugs
OSS-Fuzz will report some bugs that are labeled `Reliably reproduces: NO` and
these can be tricky to deal with. A non-reproducible bug is an issue that
OSS-Fuzz did indeed discover, however, OSS-Fuzz is unable to reproduce the bug
with `python infra/helper.py reproduce`. In general, our suggestion is to do
analysis of the bug and determine whether there in fact is an issue.

The non-reproducible bugs can be of varying nature. Some of these bugs will be
due to some internal state of the target application being manipulated over the
cause of several executions of the fuzzer function. This could be several
hundreds or even thousands of executions and the bug may not be reproducible by
a single fuzzer test-case, however, there is indeed a bug in the application.
There are other reasons why bugs may be non-reproducible and in general any
non-determinism introduced into the application can have an effect on this.

In the case of non-reproducible bugs our advice is to put effort into analysing
the potential bug and also assess whether this is due to some internal state
that persists between each fuzz run. If that is indeed the case then we also
suggest investigating whether the fuzzer can be written such that the internal
state in the code will be reset between each fuzz run.

## Should all reported issues be solved?
It is reported by some project maintainers that fixing timeout issues reported
by OSS-Fuzz can increase the complexity of the project’s source code. The
result of this is that maintainers put effort into solving a timeout issue and
the fix results in additional complexity of the project. The question is
whether in a scenario like this if the overall result actually improves the
state of the application.

In order to answer this question we must assess the issue relative to the
threat model. Following the timeout anecdote then some timing issues can have
severe security implications. For example, if the timeout issue can cause
manipulation of control-flow then the timing issue may be of high security
severity. As such, it is difficult to say in the general case whether or not
some bugs should not be solved, as it should be analysed and determined on a
project-by-project basis.

In the event that a bug is reported by OSS-Fuzz that is not relevant to
security or reliability of the application then there may still be a point to
fixing the bug. For example, if the issue is often run into by the fuzzer then
the fuzzer may have difficulty exploring further code in the target, and thus
fixing the bug will allow the fuzzer to explore further code. In this case some
suggested examples of resolving the issue could be:
* Perform a hot-patch that is only applied during fuzzer executions and does
not overcomplicate the project’s code.
* Patch the code of the fuzzer to avoid the timeout. For example, some fuzzers
restrict the size of the input to avoid certain deep recursions or
time-intensive loops.
* Patch the code in the target despite complicating things.
