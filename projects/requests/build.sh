#!/bin/bash -eu
pip3 install atheris requests
compile_python_fuzzer fuzz_requests.py
