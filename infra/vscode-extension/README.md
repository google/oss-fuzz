# Visual studio code extension

NB: This is in progress.


# To use:
Open the folder in vscode. Use `f5` to launch the extension runner, and
then `ctrl-shift-p` to run commands. Commands supported are prefixed with
`OSS-Fuzz`.

Example workflow. Run the commands:

1. *OSS-Fuzz: Set up OSS-Fuzz* This will download the OSS-Fuzz repository and store it in `/tmp/oss-fuzz`.
2. *OSS-Fuzz: Build fuzzers* This will prompt for a project name, which will then build the fuzzers for the given project.
3. *OSS-Fuzz: Run fuzzer from OSS-Fuzz project* This will prompt for a project name, fuzzer name and duration and start running the fuzzer using OSS-Fuzz infrastructure.


**sync local folder with OSS-Fuzz build**. You can use the command *OSS-Fuzz: Set project path* to map a local path to a project in OSS-Fuzz, which will then cause this folder to be used for the project's source code when building the fuzzers. This is useful to e.g. sync your development environment with OSS-Fuzz such that OSS-Fuzz doesn't clone your repository from e.g. Github, but uses the local version instead. Note the local path should be absolute.


To extract a full coverage and introspector profile you can use *OSS-Fuzz: Run end-to-end Fuzz Introspector on a project*.
