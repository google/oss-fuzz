# OSS-Fuzz Helper CLI Reference (`infra/helper.py`)

This document provides a reference for the `python3 infra/helper.py` command-line interface, which is the primary tool for interacting with OSS-Fuzz projects locally.

## Global Subcommands

### `generate`
Generate files for a new project.
```bash
python3 infra/helper.py generate [--language {c,c++,go,javascript,jvm,python,ruby,rust,swift}] [--external] <project>
```
- `--language`: Specify the project language.
- `--external`: Indicate if the project is external.

### `build_image`
Build a project's Docker image.
```bash
python3 infra/helper.py build_image [--pull] [--no-pull] [--architecture {i386,x86_64,aarch64}] [--cache] [--external] <project>
```
- `--pull`: Pull the latest base image before building.
- `--no-pull`: Do not pull the latest base image.
- `--cache`: Use Docker cache when building the image.

You should *always* use `--pull` unless explicitly asked not to.

### `build_fuzzers`
Build fuzzers for a project.
```bash
python3 infra/helper.py build_fuzzers [--architecture ARCH] [--engine ENGINE] [--sanitizer SANITIZER] [-e VAR=val] [--clean] [--no-clean] <project> [source_path]
```
- `--architecture`: Target architecture (default: `x86_64`).
- `--engine`: Fuzzing engine (default: `libfuzzer`).
- `--sanitizer`: Sanitizer to use (default: `address`). Options: `address`, `memory`, `undefined`, `thread`, `coverage`, `introspector`, `hwaddress`.
- `-e`: Set environment variables in the build container.
- `--clean`: Clean existing artifacts before building.
- `source_path`: Optional path to local source code to mount into the container.

In the vast majority of cases you should simple use `python3 infra/helper.py build_fuzzers PROJECT_NAME` without any options.

### `check_build`
Verify that built fuzzers execute without errors (checks if they can run for a few seconds).
```bash
python3 infra/helper.py check_build [--architecture ARCH] [--engine ENGINE] [--sanitizer SANITIZER] <project> [fuzzer_name]
```

### `run_fuzzer`
Run a specific fuzzer in the emulated fuzzing environment.
```bash
python3 infra/helper.py run_fuzzer [--architecture ARCH] [--engine ENGINE] [--sanitizer SANITIZER] [--corpus-dir CORPUS_DIR] <project> <fuzzer_name> [fuzzer_args ...]
```
- `fuzzer_args`: Arguments passed directly to the fuzzing engine (e.g., `-max_total_time=60`, `-runs=100`).

### `coverage`
Generate a code coverage report for the project.
```bash
python3 infra/helper.py coverage [--no-corpus-download] [--no-serve] [--port PORT] [--fuzz-target FUZZ_TARGET] <project> [extra_args ...]
```
- `--no-corpus-download`: Use local corpus instead of downloading from OSS-Fuzz.
- `--fuzz-target`: Specify a specific fuzz target to generate coverage for.
- `--no-serve`: Do not start a local web server to view the report.

### `reproduce`
Reproduce a crash using a local testcase.
```bash
python3 infra/helper.py reproduce [--valgrind] <project> <fuzzer_name> <testcase_path> [fuzzer_args ...]
```
- `testcase_path`: Path to the file containing the input that caused the crash.

### `shell`
Start an interactive shell within the project's builder container.
```bash
python3 infra/helper.py shell [--architecture ARCH] [--engine ENGINE] [--sanitizer SANITIZER] <project> [source_path]
```
- Useful for debugging build issues manually.

### `pull_images`
Pull the latest OSS-Fuzz base images.
```bash
python3 infra/helper.py pull_images
```

## Common Options
Most subcommands support:
- `--architecture`: `{i386,x86_64,aarch64}`
- `--engine`: `{libfuzzer,afl,honggfuzz,centipede,none,wycheproof}`
- `--sanitizer`: `{address,none,memory,undefined,thread,coverage,introspector,hwaddress}`
- `--external`: If the project is not in the `projects/` directory.
