#!/bin/bash -eu

# Define a variable for the repeated path
SECRETS_SAFE_PATH="$SRC/ps-integration-ansible/beyondtrust/secrets_safe"

# Install Python dependencies from the mounted requirements.txt file
pip install --upgrade pip
pip install -r "$SECRETS_SAFE_PATH/requirements.txt"

# Compile the fuzz target
python3 -m compileall "$SECRETS_SAFE_PATH/fuzz_secrets_safe_lookup.py"

# Move the fuzz target to the output directory
cp "$SECRETS_SAFE_PATH/fuzz_secrets_safe_lookup.py" "$OUT/fuzz_secrets_safe_lookup"