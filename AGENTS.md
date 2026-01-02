# OSS-Fuzz Developer Guide

## Overview
OSS-Fuzz is a continuous fuzzing infrastructure for open source software.

## Key Directories
- `projects/`: Contains individual project configurations. Each project has:
  - `project.yaml`: Metadata.
  - `Dockerfile`: Build environment.
  - `build.sh`: Build script.
- `infra/`: Infrastructure code and helper scripts.
- `docs/`: Documentation.

## Local Development
The primary tool for local development is `infra/helper.py`.

### Common Commands
All commands assume you are in the root of the OSS-Fuzz repository.

1.  **Build Docker Image:**
    ```bash
    python3 infra/helper.py build_image $PROJECT_NAME
    ```

2.  **Build Fuzzers:**
    ```bash
    python3 infra/helper.py build_fuzzers --sanitizer <address|memory|undefined> $PROJECT_NAME
    ```
    *Options:* `--sanitizer`, `--engine` (libfuzzer, afl, honggfuzz), `--architecture` (x86_64, i386).

3.  **Run Fuzzer (Interactive/Verification):**
    ```bash
    python3 infra/helper.py run_fuzzer --corpus-dir=<path-to-temp-corpus> $PROJECT_NAME <fuzz_target>
    ```

4.  **Reproduce Crash:**
    ```bash
    python3 infra/helper.py reproduce $PROJECT_NAME <fuzz_target> <testcase_path>
    ```

5.  **Check Build (Sanity Check):**
    ```bash
    python3 infra/helper.py check_build $PROJECT_NAME
    ```

6.  **Generate New Project Template:**
    ```bash
    python3 infra/helper.py generate $PROJECT_NAME --language=$LANGUAGE
    ```

## CI & Testing
Workflows are defined in `.github/workflows`.

### Infrastructure Tests (`infra/presubmit.py`)
Run these tests when modifying code in `infra/`.
- **Command:** `python infra/presubmit.py infra-tests -p`
- **Requirements:**
  - Python 3.11
  - Dependencies: `infra/ci/requirements.txt`, `infra/build/functions/requirements.txt`, `infra/cifuzz/requirements.txt`
  - `gcloud beta cloud-datastore-emulator`

### Project Tests (`infra/ci/build.py`)
These run in CI to verify project builds across different engines and sanitizers.
- **Command:** `python infra/ci/build.py`
- **Environment Variables:** `ENGINE`, `SANITIZER`, `ARCHITECTURE`
- **Requirements:** `infra/ci/requirements.txt`

## Documentation
- `docs/getting-started/new_project_guide.md`: Detailed guide on adding new projects.
- `docs/advanced-topics/reproducing.md`: How to reproduce issues.
