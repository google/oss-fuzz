+++
authors = ["OSS-Fuzz Maintainers"]
title = "OSS-Fuzz integrations via agent-based build generation"
date = "2025-05-25"
description = "OSS-Fuzz integrations via agent-based build generation."
categories = [
    "Fuzzing",
    "Fuzzing synthesis",
    "LLM",
    "Automated fuzzing",
    "Automated build script generation",
]
+++


# Introduction

As part of the [OSS-Fuzz-Gen](https://github.com/google/oss-fuzz-gen) project we have been working on making it easier for maintainers to integrate projects into OSS-Fuzz. Since OSS-Fuzz requires a specific build script in a format that uses the OSS-Fuzz build environment, the problem of automating OSS-Fuzz integrations is largely split in two parts: (1) creating a script for building the target project and relevant fuzzing harnesses and (2) creating the actual fuzzing harness. As such, any solution looking to automate OSS-Fuzz integrations must be able to solve both of these problems for a diverse set of open source projects.

The key goal for automating OSS-Fuzz integration is to support a full workflow that takes as input a project, e.g. GitHub repository, that is not integrated into OSS-Fuzz and outputs a generated OSS-Fuzz project with a working build script and one or more fuzzing harnesses. Furthermore, this workflow should be easily accessible and deployable, so open source maintainers can quickly leverage its features.

The primary focus of OSS-Fuzz-Gen has so far been on generating fuzzing harnesses for existing OSS-Fuzz projects. In a previous [blog post](https://blog.oss-fuzz.com/posts/introducing-llm-based-harness-synthesis-for-unfuzzed-projects/) we documented an end-to-end approach for OSS-Fuzz integrations, however, there were several significant limitations to this approach that meant it did not sufficiently solve the problems described above. Specifically, the build script generation was based on a template-based strategy and this had limitations in terms of being able to create build scripts for a diverse set of projects. In this blog post, we present two improvements towards an end-to-end OSS-Fuzz integration workflow:

1) An agentic LLM-based approach for build script generation.
2) A CLI tool making this easy to access and run.



# Overview and sample run

The main goal of our approach is to automate the full end-to-end generation of an OSS-Fuzz project, by simply providing as input one or more Git repositories and then outputting a list of one or more OSS-Fuzz integrations. We expose these capabilities as a CLI in a Python package which makes it easy to install and run. To demonstrate the capabilities and give an intuition for the workflow, consider the below sample which generates an OSS-Fuzz project, including fuzzing harnesses, for [https://github.com/zserge/jsmn](https://github.com/zserge/jsmn). 

```sh
# Prepare virtual environment
python3.11 -m virtualenv .venv
. .venv/bin/activate

# Clone OSS-Fuzz-gen
git clone https://github.com/google/oss-fuzz-gen
cd oss-fuzz-gen

# Install OSS-Fuzz-gen
python3 -m pip install .


# Generate fuzzers for https://github.com/zserge/jsmn
echo "https://github.com/zserge/jsmn" > input.txt

# Run the generation
# Setup Vertex AI access: https://github.com/google/oss-fuzz-gen/blob/main/USAGE.md#llm-access
oss-fuzz-generator generate-full -i input.txt -m vertex_ai_gemini-2-flash-chat --agent -w work-1

# List the files of generated project
$ ls final-oss-fuzz-projects/jsmn-agent/
build.sh  Dockerfile  empty-fuzzer.0.c  empty-fuzzer.1.c  project.yaml
```

The first step is to install the Python package, which is currently done by cloning OSS-Fuzz-Gen and then installing it using `python -m pip install .`. The installed package includes a CLI tool `oss-fuzz-generator` which exposes the OSS-Fuzz project generation capabilities. The only step following this is to set up your LLM environment and use the `generate-full` command. This command will generate a build script as well as fuzzing harnesses, and also merge all successful fuzzing harness into one single OSS-Fuzz project.

More specifically, `oss-fuzz-generator generate-full` will perform three main steps for each of the repositories in the `input.txt` file:
1) Generate a build script that will compile fuzzers of a given project
2) If step 1 was successful, generate fuzzing harnesses for the project
3) Merge successful fuzzing harnesses into a single OSS-Fuzz project

In this blog post, we will focus on step 1 above.


# Agent-based build generation

The agent-based approach to generating build scripts rely on three central components. First, an initial prompt that outlines the overall task and constraints for creating build scripts for a given arbitrary repository. Second, an agent that communicates with the LLM and executes arbitrary commands, provided by the LLM, within the environment where the build script will be run, allowing the LLM to explore the runtime environment. Third, a process for running generated build scripts as well as executing generated fuzzers to guide the output from the LLM. The overall algorithm for the agentic build generation workflow is as follows:


```
initial_prompt = prepare_initial_prompt(target_repository)

prompt = prepare_initial_prompt(target_repository)
llm_client = llm_start_chat()
while should_keep_going():
    llm_response = llm_client.chat(prompt)
    res = parse_llm_response(llm_response)
    if res.is_commands() {
      output = execute_commands(res.get_commands());
    }
    else if (res.has_build_script()) {
      output = build_and_run_fuzzer(res.get_build_script(), res.get_fuzz_harness());
      if (output.has_successful_build_script()) {
        // Success in harness generation
        return output
      }
    }
    else {
      // Failure happened in parsing LLM output
      exit()
    }   

    // Prepare a next prompt for the LLM to chat.
    prompt = prepare_next_prompt(output);
```

The algorithm returns a successful build script if the `return output` line is reached. Specifically, this line is reached when the LLM has created a build script with an accompanying fuzz harness that can successfully build and link against the code of the target repository.

There are four key functions in the build generation algorithm:

- *parse_llm_response*: takes as input the raw text returned by the LLM and converts it into either (1) a list of commands to execute in the runtime environment where the fuzzers are build or (2) a build script with supplied fuzzing harness source code. The LLM is initially instructed in the prepare_initial_prompt to generate text that conforms to a given standard, such as by wrapping output in XML tags.
- *execute_commands*: if the LLM returns a list of commands as determined by `parse_llm_response`, then this function executes these commands in the runtime environment in which the build script is to be run. The main point of this is that it enables the LLM to explore, understand and test the runtime environment. Results from running the commands are returned to the LLM and since the agent runs in a loop, the LLM can continuously issue commands, interpret the output and act accordingly.
- *build_and_run_fuzzer*: if the LLM returns a build script and potentially a fuzzing harness (it may be empty) as determined by the `parse_llm_response`, then this function will build these artifacts in the runtime environment. The output of the build will be analysed, and, if a successful harness was built then the process is considered completed. In case the build was not successful, then the output of executing the build script is saved and will eventually be passed back to the LLM.
- *prepare_next_prompt*: in the event that the iteration did not result in a successful build script, which can happen either if the LLM had returned a set of commands or the returned build script failed, the output of this will be used to construct a next prompt for the LLM. Specifically, we use the output from `execute_commands` and `build_and_run_fuzzer` as input to the next prompt. The prompt itself wraps around the output with a lightweight textual description. This prompt will then be used in the next agent iteration and passed to `llm_client.chat`.


The output of the above algorithm is upon success a build script that can produce a successful fuzzing harness. The next step is then to use this build script as the foundation of an OSS-Fuzz project, and use OSS-Fuzz-Gen’s core capabilities of generating fuzzing harnesses for an OSS-Fuzz project.

# Empirical evaluation

To test our approach, we ran this on a set of GitHub repositories written in C/C++. In total we analysed 225 repositories which generated a total of 88 OSS-Fuzz integrations with valid build scripts. We furthermore ran the harness generation capabilities of OSS-Fuzz-Gen on these projects to confirm the validity of the build scripts. In this blog post we will focus on the results of the build generation and discuss bug-finding capabilities in a future blog post.

We found that the approach has many strengths in that it overcame hurdles posed by many of the projects, and that it’s able to create build scripts our template-based approach is not. In this section we will go through a few samples of the build scripts to highlight the capabilities and limitations of the approach.


### Libcypher-parser

Target: [https://github.com/cleishm/libcypher-parser](https://github.com/cleishm/libcypher-parser)

The build script generated for this project is:

```sh
# Build script for libcypher-parser with fuzzing harness

# Install necessary dependencies
apt-get update && apt-get install -y make autoconf automake libtool curl

# Install autoconf 2.71
cd /tmp
curl -O http://ftp.gnu.org/gnu/autoconf/autoconf-2.71.tar.gz
tar -xzf autoconf-2.71.tar.gz
cd autoconf-2.71
./configure
make
make install

# Install leg tool
cd /tmp
curl -L -O https://www.piumarta.com/software/peg/peg-0.1.18.tar.gz
tar -xzf peg-0.1.18.tar.gz
cd peg-0.1.18
make
make install

# Build libcypher-parser
cd $SRC/libcypher-parser
./autogen.sh
./configure --enable-static --disable-shared
make

# Copy the static library to the output directory
cp lib/src/.libs/libcypher-parser.a $OUT/

# Compile the fuzzing harness
for fuzzer in $(find $SRC -maxdepth 1 -name 'empty-fuzzer.*'); do
    fuzzer_basename=$(basename $fuzzer .c)
    $CC $CFLAGS -I$SRC/libcypher-parser/lib/src $fuzzer -o $OUT/${fuzzer_basename} \
        -L$OUT -lcypher-parser -Wl,--whole-archive $LIB_FUZZING_ENGINE -Wl,--no-whole-archive
done
```

Overall, this is a fairly complex build in that it installs a version of autoconf different to what is already in the runtime environment and also a tool “peg”. In order to identify that the “leg”/”peg” tool is needed, the agent had to interpret the output of the building the project without this tool, as doing so leads to the following issue when configuring libcypher-parser:

```sh
...
checking for leg... no
configure: error: leg is required: please install http://piumarta.com/software/peg/
ERROR:__main__:Building fuzzers failed.
```


### Yams

Target: [https://github.com/jpsim/Yams](https://github.com/jpsim/Yams)

The build script produced in this case is as follows:


```sh
#!/bin/bash
# Set up build environment
cd $SRC/Yams/Sources/CYaml
mkdir -p build
cd build
cmake .. -DCMAKE_C_COMPILER=$CC -DCMAKE_CXX_COMPILER=$CXX
make

# Compile the fuzzing harness
$CC $CFLAGS -I$SRC/Yams/Sources/CYaml/include -I$SRC $SRC/empty-fuzzer.c -o $OUT/empty-fuzzer -L. -Wl,--whole-archive libCYaml.a -Wl,--no-whole-archive $LIB_FUZZING_ENGINE
```

The build script is a simple cmake build script, but it passes arguments to the cmake command to ensure the target builds with the commands as specified by the OSS-Fuzz runtime environment. Interestingly, the building and linking of the fuzz harness in this context is not done in a loop. This works in principle, in that the project is able to build and link a fuzzing harness, but is limited in that it is unable to build and link and arbitrary number of fuzzing harnesses.


### Moment

Target: [https://github.com/kmussel/Moment](https://github.com/kmussel/Moment)

This is a library that has not been active for 10 years, so a particular challenge of this project is building a potentially old project. The build script generated is the following:

```sh
#!/bin/bash
# Install necessary tools
apt-get update && apt-get install -y bison flex

# Set source and output directories
SRC_DIR="$SRC/Moment"
OUT_DIR="$OUT"

# Preprocess parseIt.ym to remove the Foundation import
sed '/#import <Foundation\/Foundation.h>/d' $SRC_DIR/parseIt.ym > $SRC_DIR/parseIt_preprocessed.ym

# Use bison to generate parseIt.c and y.tab.h
bison -d -o $SRC_DIR/parseIt.c $SRC_DIR/parseIt_preprocessed.ym

# Rename the generated header to y.tab.h
mv $SRC_DIR/parseIt.h $SRC_DIR/y.tab.h

# Use flex to generate tokeIt.c
flex -o $SRC_DIR/tokeIt.c $SRC_DIR/tokeIt.l

# Compile the source files into object files
$CC $CFLAGS -c $SRC_DIR/TimeParser.c -o TimeParser.o
$CC $CFLAGS -c $SRC_DIR/parseIt.c -o parseIt.o
$CC $CFLAGS -I$SRC_DIR -c $SRC_DIR/tokeIt.c -o tokeIt.o

# Archive the object files into a static library
llvm-ar rcs libmoment.a TimeParser.o parseIt.o tokeIt.o

# Compile the fuzzing harness and link with the static library
$CC $CFLAGS -I$SRC_DIR $SRC/empty-fuzzer.c -o $OUT_DIR/empty-fuzzer -L. libmoment.a $LIB_FUZZING_ENGINE
```

Similar to libcypher-parser above, the impressive parts of this build script is the complexity of it, and the ability to download and install custom packages, and using the tools of these packages as part of the build script process. The build script adjusts a file in the target project using `sed` and runs several tools, bison and flex, to generate code needed for the compilation. Furthermore, the project itself does not have any build system files, e.g. `Makefile` and consequently the build agent reverts to compiling the source files directly.


# Limitations and future work

During our empirical evaluation we observed several limitations and possible improvements.

### Build scripts that succeed but avoid target source code
We observed several cases where the agent produces build scripts that simply avoid building the target source code and just end up building an empty fuzzing harness. The problem is that the approach currently does not do post-processing analysis on the generated harness in terms of validating that the target source code is part of the resulting binary. The problem in this case is that when the process moves on to harness generation, then the build script is not able to support the workflow because no building of the target source code is involved. Although this was a rare occurrence, a required solution is to have more rigorous post processing to validate the completeness of the build script generated, or the ability to adjust later in the end-to-end workflow.

### Build scripts that can only build a single fuzzing harness
The approach instructs the LLMs to generate build scripts that can build an arbitrary number of fuzzing harnesses. This is to make it possible to use the build script for building and linking any number of fuzzing harnesses that the harness-generation part of OSS-Fuzz-gen produces. It is likely OSS-Fuzz-gen will end up producing more than one valuable fuzzing harness, and the build script should be able to build them all at the same time. We observed that this constraint is not always accepted and some build scripts end up with the capability of only building a single fuzzing harness, e.g. due to lack of a loop in the build instructions. The problem in this case is that the user of the tool will have to adjust the build script such that it can build an arbitrary number of fuzzing harnesses, assuming that two or more fuzzing harnesses are needed for the final OSS-Fuzz integration.

### Integrating into target codebase’s build configurations
The current approach often yields build scripts that explicitly link fuzzing harnesses using CXX or CC environment variables to link against static libraries built earlier in the build script. As such, the build scripts are composed of a set of commands as well as a fuzzing harness source code. Another approach would be to integrate the building of the fuzzers into the build system of the target repository, such as by extending Makefiles and alike. Although this won’t have any practical difference as such, it may make the approach more friendly towards developers.

### Diagnosis and conclusions on failed generation
In the case where the build script generation failed, there is at the moment no real explanation as to why it failed. An extension to the workflow is to have another agent or similar, that analyse the reason why the build failed. For example, it is valuable to know if the reason for failing is a hard reason such as the code cannot be compiled in the relevant build runtime, or whether the LLM simply wasn’t capable of finding a proper solution. In case the reason is a hard reason, that is in a sense a positive conclusion since it can explicitly tell the user that the target project is not compatible with OSS-Fuzz (such as, if it’s a Windows-only project).

# Conclusion

In this blog post we have introduced a new capability of [OSS-Fuzz-Gen](https://github.com/google/oss-fuzz-gen) for producing OSS-Fuzz project integrations from scratch via an agent-based approach to build script generation. This is available through a CLI tool and only a single command is required for generating an OSS-Fuzz project. We ran the approach against a set of 225 projects which resulted in 88 OSS-Fuzz build scripts, and to highlight the capabilities we went through a set of these as well as identified limitations and future work.

The tooling is available on GitHub at [https://github.com/google/oss-fuzz-gen/tree/main/experimental/end_to_end](https://github.com/google/oss-fuzz-gen/tree/main/experimental/end_to_end) and we encourage users to try and run the tooling on their projects of interest. We are always happy to hear about projects where the build generation is not working and welcome users to submit this information as GitHub issues in the above repository.