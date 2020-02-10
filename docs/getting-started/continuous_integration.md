---
layout: default
title: Continuous Integration
parent: Getting started
nav_order: 5
permalink: /getting-started/continuous-integration/
---

# Continuous Integration

OSS-Fuzz offers Continuous Integration(CI) support for projects hosted on
GitHub. This service is called CIFuzz and can be used to run OSS-Fuzz fuzz targets
on your project when a pull request is submitted. It has the advantage of
detecting bugs before they are committed into your project. This insures that
less bugs are committed meaning less active security vulnerabilities.

## How it works

CIFuzz works by checking out a repository at the head of a pull request. The
project's fuzz targets are built and run for
a definite amount of time (default is 10 minutes). If a bug is found, the
stack trace as well as the test case are surfaced to the user. If a bug is
not found the test passes with a green check.

## Requirements
1. Your project must be integrated in OSS-Fuzz.
1. Your project is hosted on GitHub.

## Integrating into your repository
You can integrate CIFuzz into your project using the following steps:
1. Create a `.github` directory in the root of your project.
1. Create a `workflows` directory inside of your `.github` directory.
1. Copy the example [`main.yml`](https://github.com/google/oss-fuzz/blob/master/infra/cifuzz/example_main.yml)
file over from the OSS-Fuzz repository to your workflows directory.

Your directory structure should look like the following:
```
project
|___ .github
|    |____ workflows
|          |____ main.yml
|___ other-files
```

 Your main.yml file should look like the following:

```
name: CIFuzz
on: [pull_request]
jobs:
 Fuzzing:
   runs-on: ubuntu-latest
   steps:
   - name: Build Fuzzers
     uses: google/oss-fuzz/infra/cifuzz/actions/build_fuzzers@master
     with:
       project-name: 'example'
       dry-run: false
   - name: Run Fuzzers
     uses: google/oss-fuzz/infra/cifuzz/actions/run_fuzzers@master
     with:
       fuzz-time: 600
       dry-run: false
   - name: Upload Crash
     uses: actions/upload-artifact@v1
     if: failure()
     with:
       name: bug_report
       path: ./out/bug_report
```

4. Change the `project-name` value in `main.yml` from `example` to the name of your OSS-Fuzz project. It is IMPORTANT that you use your OSS-Fuzz project name which is case sensitive. This name
is what your project is refered to in the [`projects`](https://github.com/google/oss-fuzz/tree/master/projects) directory of OSS-Fuzz.

### Optional configuration
`fuzz-time`: Can be used to change how long your project is given to fuzz in seconds.
The default is 600 seconds. The GitHub Actions max run time is 21600 seconds.

`dry-run`: Can be used to determine if the CI tool surfaces errors. When dry run is enabled,
fuzzing will happen as normal but a red X will not appear on GitHub if a bug is found.
This requires the user to manually check the logs for detected bugs. If dry run mode is desired,
make sure to set the dry-run parameters in both the `Build Fuzzers` and `Run Fuzzers` action steps.

## Understanding results
The results of CIFuzz can be found in two different places.

* The run fuzzers log.
    1. This log can be accessed in the `actions` tab of a CIFuzz integrated repo.
    1. Click on the CIFuzz in the workflow selector on the left hand side.
    1. Click on the event triggered by your desired pull request.
    1. Click the Fuzzing workflow.
    1. Select the Run Fuzzer drop down. It should show the timestamps and results
    from each of the fuzz targets.


*  The bug_report artifact
    1. In the event of an error the Run Fuzzers section of the workflow the Upload Artifact
    event should be triggered.
    1. This will cause a pop up in the left hand corner, allowing
    you to download a zipped folder called bug_report.
    1. bug_report is a zipped folder with two files in it.
        * `test_case` - Is a test case that can be used to reproduce the bug.
        * `bug_summary` - Is the stack trace and summary of the detected bug.

## Feedback

Create an issue in [OSS-Fuzz](https://github.com/google/oss-fuzz/issues/new).
