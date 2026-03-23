---
name: oss-fuzz-engineer
description:
  Use this skill to interact with the OSS-Fuzz infrastructure.
---

# OSS-Fuzz engineer

This skill guides the agent how to use the OSS-Fuzz infrastructure to find and report bugs in open source software. The agent can use this skill to integrate new projects, extend and improve the fuzzing posture of projects, run fuzzing campaigns, and fix broken existing OSS-Fuzz projects.

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

Use the local code coverage feature of the `python3 infra/helper.py` tool to generate code coverage reports for fuzz targets locally, for example to validate the code coverage achieved by a new fuzz target. This can be done by running `python3 infra/helper.py introspector --coverage-only PROJECT_NAME` and then studying the generated report in e.g. build/out/PROJECT_NAME/report.

The user may provide directions on how to extend the fuzzing, and it's crucial to follow instructions on this matter. For example, the user may ask to focus on a specific area of the code, or to target specific types of vulnerabilities. The agent should always provide a clear explanation of the rationale for each extension or improvement made to the fuzzing posture of the project.

When extending an OSS-Fuzz project it's crucial to have a good understanding of the target code. To this end, it's often useful to get a local version of the target source code into the OSS-Fuzz project structure to make working with the target project easy. This involves e.g. studying the `Dockerfile` of the target project, finding the e.g. `git clone` of the target project, and then cloning this repository locally and using e.g. `COPY` instead of `RUN git clone` in the Dockerfile to get the source code into the container.

The agent should always provide clear technical justification for each extension.

When doing this type of work it's crucial the agent uses any skills it has related to code analysis and fuzzing harness writing. It's important each extension is done through a personal assessment of the current fuzzing posture of the project, and a clear explanation of the rationale for each extension or improvement. The agent should never make any commits or push anything to GitHub, but should conclude on the work for the security engineer to review. The agent should never submit any changes to OSS-Fuzz's Github.


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
