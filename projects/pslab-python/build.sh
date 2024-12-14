#!/bin/bash -eu

# Install Python dependencies for PSLab
pip3 install --no-cache-dir -r $SRC/pslab-python/requirements.txt

# Copy the fuzzer file to the output directory
cp $SRC/pslab_fuzzer.py $OUT/pslab_fuzzer
