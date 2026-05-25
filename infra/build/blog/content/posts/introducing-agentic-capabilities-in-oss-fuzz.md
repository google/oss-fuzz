+++
authors = ["OSS-Fuzz Maintainers"]
title = "Introducing agentic capabilities and OSS-Fuzz"
date = "2026-05-14"
description = "Introducing agentic capabilities and OSS-Fuzz."
categories = [
    "Fuzzing",
    "Fuzzing synthesis",
    "LLM",
    "Automated fuzzing",
    "Agentic coding",
]
+++


# Introduction

In the last few months OSS-Fuzz has worked on introducing agentic capabilities into its repository to automate tasks related to fuzzing. These efforts build on the success observed from CLI agents like gemini-cli and Claude Code, and also builds on earlier efforts, e.g. [OSS-Fuzz-Gen](https://github.com/google/oss-fuzz-gen) and [Fuzz Introspector](https://github.com/ossf/fuzz-introspector), where we have developed tools and ideas for automating fuzz harness creation, fuzz harness improvements and so on. The success of CLI agents in generating code has changed how we write fuzzing harnesses and in general improve the fuzzing posture of a given open source project. In OSS-Fuzz we intend to make this as accessible as possible as well as assist in using these tools to improve fuzzing of open source software. To support this, we have developed agent skills and lightweight infrastructure that can be used to automate common OSS-Fuzz tasks, such as:

1. Onboarding a new project.
2. Improve code coverage of existing OSS-Fuzz projects.
3. Fixing a broken build of a project.
4. General tasks related to OSS-Fuzz.

The use of these skills and helper infrastructure significantly reduces the effort needed to do a lot of the technical work around fuzzing open source projects. We have used these skills to expand existing OSS-Fuzz projects and while the technical efforts are significantly reduced there is still work for each expansion related to reviewing the output, coordinating with the project maintainers and so on. In this blog post we will go through these efforts and the results that we have achieved.

# The infrastructure: Prompts, skills and helper scripts

At the core of the agentic prompt are a selection of skills that can be used for working with OSS-Fuzz. These skills are available in [infra/experimental/agent-skills/](https://github.com/google/oss-fuzz/tree/master/infra/experimental/agent-skills). They contain high-level descriptions for how to perform fuzzing-related tasks and also how to handle OSS-Fuzz infrastructure. An easy way to get started with these skills are simply to copy the skills to your global skills folder for your relevant CLI agent, launching the CLI and then querying the agent to perform a task. To load the skills in the global Gemini cli folder:

```bash
$ git clone https://github.com/google/oss-fuzz                                                                                               
$ cd oss-fuzz/
$ ./infra/experimental/agent-skills/copy_to_global.sh gemini
Copying skills to global skills directory: /home/dav/.gemini/skills
Copying /home/dav/oss-fuzz-test/oss-fuzz/infra/experimental/agent-skills/fuzzing-memory-unsafe-expert to /home/dav/.gemini/skills/
Copying /home/dav/oss-fuzz-test/oss-fuzz/infra/experimental/agent-skills/fuzzing-go-expert to /home/dav/.gemini/skills/
Copying /home/dav/oss-fuzz-test/oss-fuzz/infra/experimental/agent-skills/fuzzing-rust-expert to /home/dav/.gemini/skills/
Copying /home/dav/oss-fuzz-test/oss-fuzz/infra/experimental/agent-skills/fuzzing-jvm-expert to /home/dav/.gemini/skills/
Copying /home/dav/oss-fuzz-test/oss-fuzz/infra/experimental/agent-skills/fuzzing-python-expert to /home/dav/.gemini/skills/
Copying /home/dav/oss-fuzz-test/oss-fuzz/infra/experimental/agent-skills/oss-fuzz-engineer to /home/dav/.gemini/skills/
```


Once the skills have been copied we can simply load the skills in our agent CLIs and start asking it to perform OSS-Fuzz tasks:


```bash
$ gemini
...
...
/oss-fuzz-engineer Make an initial integration of https://github.com/google/knusperli
...
…
…
✦ I have successfully integrated google/knusperli into OSS-Fuzz.

  Integration Summary:
   - Project Name: knusperli
   - Fuzzer: fuzz_decode.cc, which exercises ReadJpeg in multiple modes, DecodeJpegToRGB, and HasYCbCrColorSpace.
   - Build System: Manual compilation of C++ files for simplicity and robustness, linking against lodepng.
   - Verification: Both infra/helper.py build_fuzzers and infra/helper.py check_build passed successfully.

  Files Created:
   1. projects/knusperli/project.yaml: Metadata for the project.
   2. projects/knusperli/Dockerfile: Environment setup, including cloning dependencies.
   3. projects/knusperli/build.sh: Build script for the fuzzer.
   4. projects/knusperli/fuzz_decode.cc: The fuzzing harness.

  I have verified the build and ensured it meets OSS-Fuzz standards. The project is now ready for review and submission to the OSS-Fuzz repository.
```

It is simply that straightforward to generate the set up for an initial OSS-Fuzz integration at this point, simply asking the CLI agent to do it for you. The agent will have validated that the project builds and that the fuzzers are running well, as well as most likely having done some code coverage analysis on the fuzzer. At this point, the user can naturally communicate with the agent to extract further information or extend the fuzzing of the project further. The changes done by the CLI agent will be placed in the local OSS-Fuzz checkout, making it easy to see the changes done using `git diff ./`. Intentionally we instruct the skills not to make any commits.


Following the creation of the code and OSS-Fuzz scripts, there are several more steps involved, such as reviewing the code, ensuring the fuzzing set up is integrated with the target repository and so on.

The skills itself are geared to support the most  common workflows in OSS-Fuzz:
- Integrating a new OSS-Fuzz project [infra/experimental/agent-skills/oss-fuzz-engineer/SKILL.md#integrating-a-new-project](https://github.com/google/oss-fuzz/blob/master/infra/experimental/agent-skills/oss-fuzz-engineer/SKILL.md#integrating-a-new-project)
- Extending an already existing project with additional fuzzing harnesses: [infra/experimental/agent-skills/oss-fuzz-engineer/SKILL.md#extending-and-improving-fuzzing-posture](https://github.com/google/oss-fuzz/blob/master/infra/experimental/agent-skills/oss-fuzz-engineer/SKILL.md#extending-and-improving-fuzzing-posture)
- Fixing the broken builds of an existing project: [infra/experimental/agent-skills/oss-fuzz-engineer/SKILL.md#fixing-broken-existing-oss-fuzz-projects](https://github.com/google/oss-fuzz/blob/master/infra/experimental/agent-skills/oss-fuzz-engineer/SKILL.md#fixing-broken-existing-oss-fuzz-projects)


The skills themselves are aware of common OSS-Fuzz workflows, such as code coverage collection, best practices and more. To this end, it aims to mimic what are the common best practices that would be used in an OSS-Fuzz context.

In addition to the general oss-fuzz-engineer skill we also provide skills for:

- Go-fuzzing expert: [infra/experimental/agent-skills/fuzzing-go-expert](https://github.com/google/oss-fuzz/tree/master/infra/experimental/agent-skills/fuzzing-go-expert)
- Java fuzzing expert: [infra/experimental/agent-skills/fuzzing-jvm-expert](https://github.com/google/oss-fuzz/tree/master/infra/experimental/agent-skills/fuzzing-jvm-expert)
- C/C++ fuzzing expert: [infra/experimental/agent-skills/fuzzing-memory-unsafe-expert](https://github.com/google/oss-fuzz/tree/master/infra/experimental/agent-skills/fuzzing-memory-unsafe-expert)
- Python fuzzing expert: [infra/experimental/agent-skills/fuzzing-python-expert](https://github.com/google/oss-fuzz/tree/master/infra/experimental/agent-skills/fuzzing-python-expert)
- Rust fuzzing expert: [infra/experimental/agent-skills/fuzzing-rust-expert](https://github.com/google/oss-fuzz/tree/master/infra/experimental/agent-skills/fuzzing-rust-expert)


The [oss-fuzz-engineer](https://github.com/google/oss-fuzz/tree/master/infra/experimental/agent-skills/oss-fuzz-engineer) skill, as shown in the above example, is a general skill for carrying out oss-fuzz tasks and is instructed to rely on the other skills when it sees fit. The language-specifc skills are focused on pure fuzzing, so the idea is to combine pure fuzzing skills with oss-fuzz skills to enable a complete workflow with oss-fuzz. The idea is that part of the OSS-Fuzz workflow is to write fuzzing harnesses, which does not necessarily require OSS-Fuzz expertise, but making sure the fuzzing harnesses operate well in an OSS-Fuzz environment does require OSS-Fuzz knowledge. 

## Helper scripts for larger-scale efforts

The skills themselves provide enough ground to operate effectively on OSS-Fuzz projects using CLI agents. However, it may be desirable to do larger-scale runs that exercise the same task on a number of OSS-Fuzz projects. To support this feature, we have added a helper script in [infra/experimental/agent-skills/helper.py](https://github.com/google/oss-fuzz/blob/master/infra/experimental/agent-skills/helper.py). This script makes it possible to run CLI agents in headless mode while carrying out common OSS-Fuzz tasks for the target projects.

To use the helper script to expand on the three existing OSS-Fuzz projects open62541, json-c and htslib we can simply run:

```bash
python infra/experimental/agent-skills/helper.py expand-oss-fuzz-projects \
      open62541 json-c htslib
```

Similarly, we can use it to automatically repair broken OSS-Fuzz projects if their build process has broken:

```bash
python infra/experimental/agent-skills/helper.py fix-builds \
      open62541 json-c htslib

```

The helper script will run the CLI agents in a headless mode and in a YOLO-format. As such, you should use these tools in environments you completely trust as they will execute arbitrary code in the environment. In general, running the tools should be considered executing arbitrary untrusted data.


# Running agentic improvements on 50 projects

To test the prompts and skills, we have used the skills to carry out OSS-Fuzz day-to-day tasks for a few months at this point. Additionally, we ran a larger scale experiment of agentic fuzzing expansion improvements on about 50 OSS-Fuzz projects and submitted the fuzzing harnesses to the relevant projects by contributing the harnesses to the relevant code bases. We ran the agentic in order to do fuzzing expansions, then reviewed the expansions and if our assessment was that they provide good value to the upstream projects then submitted the results.

Example pull requests that came from this include:

- GPAC fuzzing extensions: [https://github.com/gpac/testsuite/pull/58](https://github.com/gpac/testsuite/pull/58)
- Open62541 fuzzing extensions: [https://github.com/open62541/open62541/pull/8020](https://github.com/open62541/open62541/pull/8020)
- Mruby Fuzzing extensions: [https://github.com/mruby/mruby/pull/6812](https://github.com/mruby/mruby/pull/6812)
- Yara fuzzing extensions: [https://github.com/VirusTotal/yara/pull/2197](https://github.com/VirusTotal/yara/pull/2197)
- Libsodium fuzzing extensions: [https://github.com/google/oss-fuzz/pull/15433](https://github.com/google/oss-fuzz/pull/15433) 
- Sentencepiece fuzzing extensions: [https://github.com/google/oss-fuzz/pull/15222](https://github.com/google/oss-fuzz/pull/15222) and [https://github.com/google/oss-fuzz/pull/15423](https://github.com/google/oss-fuzz/pull/15423)
- Ninja fuzzing extensions: [https://github.com/ninja-build/ninja/pull/2768](https://github.com/ninja-build/ninja/pull/2768)
- Openexr fuzzing extensions: [https://github.com/AcademySoftwareFoundation/openexr/pull/2391](https://github.com/AcademySoftwareFoundation/openexr/pull/2391)
- Cpp-httplib fuzzing extensions: [https://github.com/yhirose/cpp-httplib/pull/2437](https://github.com/yhirose/cpp-httplib/pull/2437)


The Sentencepiece project we extended over two pull requests and to observe the improvements in terms of coverage we can use Fuzz Introspector to track coverage progression over time. The Fuzz Introspector page for Sentencepiece is available at [https://introspector.oss-fuzz.com/project-profile?project=sentencepiece](https://introspector.oss-fuzz.com/project-profile?project=sentencepiece) and looking at the Code Coverage graph and Fuzzer Count lines we can observe the improvements from our additions. Specifically, coverage went from 1.98% before our extensions to 40.67% after our extensions.

![image](/images/sentence_piece.png)


Similarly, the GPAC project was extended over a single iterations and we can observe the progression on the Fuzz Introspector page here [https://introspector.oss-fuzz.com/project-profile?project=gpac](https://introspector.oss-fuzz.com/project-profile?project=gpac) We observe a code coverage improvement from 15% to 22%, however, we observe the total lines of code covered by the project to go from 74,000 lines to 107,000 lines. meaning roughly 30,000 new lines of code is now analysed by the harness added.


![image](/images/gpac.png)


going from 1500 to 3000, but the percentage was lowered because the additions caused more lines to be included in the reports [https://introspector.oss-fuzz.com/project-profile?project=astc-encoder](https://introspector.oss-fuzz.com/project-profile?project=astc-encoder):

![image](/images/astc-encoder.png)

This experience with astc-encoder is a common occurrence when expanding on OSS-Fuzz projects because some parts of the target project may not be linked into the fuzzers when the fuzzers only target smaller parts of the target code base.


The skills focus primarily on improving coverage when expanding projects, although they also consider aspects such as threat model and attack surface to make the harness more effective in what really matters. From our experiences they work well with both general improvements and also targeted queries, e.g. asking to fuzz dedicated parts of a given project. This provides flexibility in terms of how one would want to fuzz a given project. For example, some projects may not be interested in fuzzing code that does not exist on the attack surface of the project and for these projects simple code coverage expansion is not necessarily desirable. To this end, we encourage maintainers to use the new agentic improvements to extend their projects in the direction that they see fit, or even moving further by providing guidance through the use of a file in the repository that details how ideally the project should be fuzzed. This will enable the agent to match the desired specification of what to fuzz with the actual implementation of the currently existing fuzzing harnesses, and then make improvements relative to the desired state.


# Moving forward

CLI agents, fuzzing and OSS-Fuzz work great in combination. The effort needed from a human perspective in terms of integrating new projects or expanding on existing projects has been dramatically reduced. There is still effort needed in terms of reviewing and validating correctness, but nonetheless the improved pace is significant.The next steps in terms of improving agentic support in OSS-Fuzz include:
Reaching out to maintainers to get feedback on the agentic skills themselves.
Continuing to use the agentic set up to narrow down the coverage gap that currently exists in OSS-Fuzz.
Integrate more relevant projects and assist maintainers along the way.

Overall, these three above tasks encompass many of the tasks at the core of OSS-Fuzz’s vision: to enable fuzzing for all critical open source projects.
