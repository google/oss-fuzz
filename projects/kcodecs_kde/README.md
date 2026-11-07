# KCodecs Fuzzer Integration (Qt/KDE Frameworks) for OSS-Fuzz

## Overview

This project provides a fuzzer integration for the [KCodecs](https://invent.kde.org/frameworks/kcodecs) library, which is part of the [KDE Frameworks](https://kde.org/products/frameworks). The fuzzer aims to discover vulnerabilities such as crashes, hangs, and memory errors when processing various text encodings using KCodecs and QTextCodec's decode/encode functionalities.

The fuzzing engine used is LibFuzzer.

## Project Structure

The `projects/kcodecs_fuzzer/` directory contains the following files:

* `Dockerfile`: Defines the Docker build environment, including the installation of necessary dependencies (Clang, Qt5, KF5Codecs).
* `build.sh`: A shell script that compiles `kcodecs_fuzzer.cc` and links it with the required Qt and KF5Codecs libraries.
* `kcodecs_fuzzer.cc`: The LibFuzzer source code, containing the `LLVMFuzzerTestOneInput` function, which feeds input data to `QTextCodec::toUnicode`.
* `corpus.tar.gz`: An initial set of test data (corpus) for the fuzzer.
* `project.yaml`: The OSS-Fuzz configuration file for this project.
* `README.md`: This file.

## Specifics and Non-Standard Solutions

During the adaptation process, the following considerations were made:

* **Qt5/KF5Codecs Dependencies:** Successful compilation required explicit installation of several `qt5-*-devel` and `kf5-kcodecs-devel` packages in the `Dockerfile`, as well as correct `CFLAGS` and `LIBS` setup in `build.sh`.
* **LibFuzzer without `main`:** The `kcodecs_fuzzer.cc` was adapted for LibFuzzer, which means the standard `main()` function was completely removed, and only `LLVMFuzzerTestOneInput()` was implemented, as LibFuzzer provides its own entry point.
* **`Qt5XmlPatterns` Linking Issues:** This was resolved by ensuring `qt5-qtxmlpatterns-devel` was present in the `Dockerfile` and passing the correct linking flags.

## Local Build Instructions (for Testing)

To build the Docker image and the fuzzer locally, follow these steps:

1.  Ensure you have Docker installed.
2.  Navigate to the root directory where your `Dockerfile`, `build.sh`, `kcodecs_fuzzer.cc`, `corpus.tar.gz`, and `project.yaml` are located.
3.  Execute the Docker image build command:
    ```bash
    docker build --no-cache -t tuner-kcodecs .
    ```

## Local Fuzzer Execution Instructions

After successfully building the image, you can run the fuzzer inside the container:

1.  Enter the container:
    ```bash
    docker run -it tuner-kcodecs /bin/bash
    ```
2.  Navigate to the directory where the fuzzer executable is located:
    ```bash
    cd /app/out
    ```
3.  Run the fuzzer:
    * For continuous fuzzing with mutations (default behavior):
        ```bash
        ./kcodecs_fuzzer
        ```
    * To process only the provided corpus (without generating new data) and then exit:
        ```bash
        mkdir corpus_dir
        tar -xzf corpus.tar.gz -C corpus_dir
        ./kcodecs_fuzzer -runs=0 corpus_dir
        ```

