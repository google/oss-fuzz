# Copyright 2024 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
################################################################################

# Collect all .spvasm files under a given directory, assemble them using
# spirv-as, and emit the assembled binaries to a given corpus directory,
# flattening their file names by replacing path separators with underscores.
# If the output directory already exists, it will be deleted and re-created.
# Files ending with ".expected.spvasm" are skipped.
#
# The intended use of this script is to generate a corpus of SPIR-V
# binaries for fuzzing.
#
# Usage:
#    generate_spirv_corpus.py <input_dir> <corpus_dir> <path to spirv-as>

import os
import pathlib
import shutil
import subprocess
import sys


def list_spvasm_files(root_search_dir):
    for root, folders, files in os.walk(root_search_dir):
        for filename in folders + files:
            if pathlib.Path(filename).suffix == ".spvasm":
                yield os.path.join(root, filename)


def main():
    if len(sys.argv) != 4:
        print("Usage: " + sys.argv[0] +
              " <input dir> <output dir> <spirv-as path>")
        return 1
    input_dir: str = os.path.abspath(sys.argv[1].rstrip(os.sep))
    corpus_dir: str = os.path.abspath(sys.argv[2])
    spirv_as_path: str = os.path.abspath(sys.argv[3])
    if os.path.exists(corpus_dir):
        shutil.rmtree(corpus_dir)
    os.makedirs(corpus_dir)

    # It might be that some of the attempts to convert SPIR-V assembly shaders
    # into SPIR-V binaries go wrong. It is sensible to tolerate a small number
    # of such errors, to avoid fuzzer preparation failing due to bugs in
    # spirv-as. But it is important to know when a large number of failures
    # occur, in case something is more deeply wrong.
    num_errors = 0
    max_tolerated_errors = 10
    logged_errors = ""

    for in_file in list_spvasm_files(input_dir):
        if ".expected." in in_file:
            continue
        out_file = os.path.splitext(
            corpus_dir + os.sep +
            in_file[len(input_dir) + 1:].replace(os.sep, '_'))[0] + ".spv"
        cmd = [
            spirv_as_path, "--target-env", "spv1.3", in_file, "-o", out_file
        ]
        proc = subprocess.Popen(cmd,
                                stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE)
        stdout, stderr = proc.communicate()
        if proc.returncode != 0:
            num_errors += 1
            logged_errors += "Error running " + " ".join(
                cmd) + ": " + stdout.decode('utf-8') + stderr.decode('utf-8')

    if num_errors > max_tolerated_errors:
        print("Too many (" + str(num_errors) +
              ") errors occurred while generating the SPIR-V corpus.")
        print(logged_errors)
        return 1


if __name__ == "__main__":
    sys.exit(main())
