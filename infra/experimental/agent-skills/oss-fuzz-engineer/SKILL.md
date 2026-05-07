---
name: oss-fuzz-engineer
description:
  Use this skill to interact with the OSS-Fuzz infrastructure.
---

# OSS-Fuzz engineer

This skill guides the agent how to use the OSS-Fuzz infrastructure to find and report bugs in open source software. The agent can use this skill to integrate new projects, extend and improve the fuzzing posture of projects, run fuzzing campaigns, and fix broken existing OSS-Fuzz projects.

When working on OSS-Fuzz tasks then you should also use any fuzzing related skills you have, such as code analysis and fuzzing harness writing skills, to achieve the best results.

## Workflows

There are multiple common workflows that an OSS-Fuzz engineer might follow and we describe some imporant ones here.

### Integrating a new project

Given a reference to an open source project, such as a link to a GitHub repository, the agent can follow these steps to integrate the project into OSS-Fuzz:
1. **Assess the project**: The agent should first assess whether the project is suitable for fuzzing. This includes checking if the project is open source, has a significant user base, and contains code that can be fuzzed (e.g., C/C++ code).
2. **Set up the environment**: The agent should set up the necessary environment for fuzzing the project. This includes:
- A Dockerfile that defines the build environment for the project, using the OSS-Fuzz base images.
- A build script that compiles the project with the necessary instrumentation for fuzzing.
- A project.yaml that provides the necessary OSS-Fuzz meta data.
3. **Write fuzz targets**: The agent should write fuzz targets for the project. Fuzz targets are small programs that call into the project's code and are used by the fuzzing engine to generate inputs and find bugs.
4. **Test the integration**: The agent should test the integration by running the fuzz targets locally and ensuring that they work correctly. This project should be continue until the fuzz targets build and run well, and the OSS-Fuzz `check_build` script passes without errors.
5. **Conclude the integration**: Once the integration is complete, the agent should conclude with a message of the results achieved and the next steps the security engineer guiding the agent should take. The agent should *not* make any commits or push anything to GitHub, but should conclude on the work for the security engineer to review. The agent should never submit any changes to OSS-Fuzz's Github.

When doing this type of work it's crucial the agent uses any skills it has related to code analysis and fuzzing harness writing.

### Extending and improving fuzzing posture

The agent can also be used to extend and improve the fuzzing posture of existing OSS-Fuzz projects. This can include:
- Adding new fuzz targets to cover more code paths and functionality.
- Improving existing fuzz targets to make them more effective at finding bugs.
- Updating the build environment to include new dependencies or tools that can enhance fuzzing.
- Analyzing fuzzing results and identifying areas of the code that are not well covered by existing fuzz targets, and then writing new fuzz targets to cover those areas.

A useful approach for extending a project is to study the latest code coverage report for the project, which is publicly available, to identify areas of the code that are not well covered by existing fuzz targets. The agent can then write new fuzz targets to cover those areas, and test them locally before concluding on the work for the security engineer to review.

Use the local code coverage feature of the `python3 infra/helper.py` tool to generate code coverage reports for fuzz targets locally, for example to validate the code coverage achieved by a new fuzz target. This can be done by running `python3 infra/helper.py introspector --coverage-only PROJECT_NAME` and then studying the generated report in e.g. build/out/PROJECT_NAME/report. Some examples of this include:

```
# Generate a coverage report for htslib OSS-Fuzz project from running each
# fuzzer for 30 seconds, and store coverage directory in `htslib-cov-1`.
python3 infra/helper.py introspector --coverage-only --seconds 30 --out htslib-cov-1 htslib

# Generate a coverage report for leveldb OSS-Fuzz project from running each
# fuzzer for 45 seconds, and store coverage directory in `leveldb-cov-1`.
python3 infra/helper.py introspector --coverage-only --seconds 45 --out leveldb-cov-1 leveldb
```

The user may provide directions on how to extend the fuzzing, and it's crucial to follow instructions on this matter. For example, the user may ask to focus on a specific area of the code, or to target specific types of vulnerabilities. The agent should always provide a clear explanation of the rationale for each extension or improvement made to the fuzzing posture of the project.

When extending an OSS-Fuzz project it's crucial to have a good understanding of the target code. To this end, it's often useful to get a local version of the target source code into the OSS-Fuzz project structure to make working with the target project easy. This involves e.g. studying the `Dockerfile` of the target project, finding the e.g. `git clone` of the target project, and then cloning this repository locally and using e.g. `COPY` instead of `RUN git clone` in the Dockerfile to get the source code into the container.

The agent should always provide clear technical justification for each extension.

When doing this type of work it's crucial the agent uses any skills it has related to code analysis and fuzzing harness writing. It's important each extension is done through a personal assessment of the current fuzzing posture of the project, and a clear explanation of the rationale for each extension or improvement. The agent should never make any commits or push anything to GitHub, but should conclude on the work for the security engineer to review. The agent should never submit any changes to OSS-Fuzz's Github.

It is crucial when extending existing OSS-Fuzz project you must validate the existing code coverage does not digress. You should empirically evaluate this and give a justification that no digression has happened, or if it has happened then you should give a justification for why the digression is acceptable in light of the achieved extension.

Unless otherwise specified, the agent should focus on improving a single fuzzing harness for the target project, and not focus on making broad changes that will take a long time to review. Simple changes are often more effective than broad large changes.

### Fixing broken existing OSS-Fuzz projects

The agent can also be used to fix broken existing OSS-Fuzz projects. This can include:
- Identifying and fixing build issues that prevent fuzz targets from running correctly.
- Updating dependencies or build scripts to ensure that the project can be fuzzed effectively.
- Analyzing fuzzing results to identify and fix issues that are causing the fuzzing campaign to fail or produce unreliable results.

A given OSS-Fuzz project must succeed with:

```
python3 infra/helper.py build_fuzzers PROJECT_NAME
python3 infra/helper.py check_build PROJECT_NAME
```

The agent should never make any commits or push anything to GitHub, but should conclude on the work for the security engineer to review. The agent should never submit any changes to OSS-Fuzz's Github.


### Chronos integration

A common task for an OSS-Fuzz engineer is to add Chronos support for a given OSS-Fuzz project.

Chronos is a feature of OSS-Fuzz that makes it possible to quickly rebuild OSS-Fuzz projects and run unit tests of a given OSS-Fuzz project. This is used to efficiently validate e.g. patches of a project without having to rebuild the entire target project image.

To add Chronos support a project needs to have two key scripts:

- replay_build.sh: used to quickly rebuild the project without network access.
- run_tests.sh: used to run unit tests of the project without network access.

There are several constraints on these scripts, e.g. no network access, and it's important to always check the infra/chronos/README.md file to understand the specifics.

A given Chronos integration must succeed with:

```sh
python3 infra/experimental/chronos/manager.py check-replay PROJECT_NAME
python3 infra/experimental/chronos/manager.py check-tests PROJECT_NAME
```

The above two commands must succeed without error, and when integrating a new project these commands must be run before concluding on the work for the security engineer to review.

In addition to the above, there are some constraints on Chronos worth mentioning:
- If the tests fail when `run_tests.sh` is run, then `check-tests` *must* fail as well. This is a crucial invariant that is used to validate if wrong patches lead to wrong outcomes, and we must be able to check wrong patches that break tests.
- The `run_tests.sh` script should leave a given repository in the state it was before the script was run. For example, `git diff` should be the same before and after `run_tests.sh` is run inside the target repository.
- `run_tests.sh` has no network connection, so if any tests requires network connection then these tests should be skipped in `run_tests.sh` and this should be clearly documented in the script.


# Guidelines for working locally on OSS-Fuzz projects

1. Always work from the base folder of the current OSS-Fuzz project unless otherwise specified.
2. Make a local checkout of the target source code to make working with the target project easy. This involves e.g. studying the `Dockerfile` of the target project, finding the e.g. `git clone` of the target project, and then cloning this repository locally and using e.g. `COPY` instead of `RUN git clone` in the Dockerfile to get the source code into the container.
3. Use the `python3 infra/helper.py` tool to build and test fuzz targets locally.
4. Analyse if build scripts can be optimized to improve local building efficiency.


# Public data available for OSS-Fuzz projects

The OSS-Fuzz infrastructure provides a lot of public data that can be used to guide the work of an OSS-Fuzz engineer. This includes:

- Current build status of all OSS-Fuzz projects:
  - html page: https://oss-fuzz-build-logs.storage.googleapis.com/index.html
  - json file: https://oss-fuzz-build-logs.storage.googleapis.com/status.json
  - use this reference to identify latest build status of a given project, and to identify if there are any build issues that need to be fixed.
  - If you are tasked with fixing the build of a project, then use this data to identify the latest build error.
  - If you are tasked with fixing the build of a project, then use this data to identify the conditions of the latest build error, e.g. which architecture, fuzzing engine and sanitizer is failing.
  - Some build errors are due to the harnesses running into an issue immediately, meaning they build but `check_build` fails. These are bugs that likely indicate the fuzzing harnesses have a deficiency.
- in the references section guidance is provided on code coverage reports, helper script used for interacting with OSS-Fuzz projects and documentation on the structure of OSS-Fuzz projects.
- https://introspector.oss-fuzz.com : details insights on macro and micro level stats on OSS-Fuzz.