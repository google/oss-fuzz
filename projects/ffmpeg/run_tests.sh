#!/bin/bash

# Usage:
#   bash run_test.sh list     - Lists all available tests
#   bash run_test.sh          - Runs all tests (same as 'make fate')
#   bash run_test.sh <filter> - Runs a specific test or group of tests
#                          (e.g., './run_test.sh acodec-pcm')

set -e # Exit immediately if any command fails

FFMPEG_SRC_DIR="/src/ffmpeg"

# if [ TODO: How can i check if ffmpeg is compiled? ]; then
#     echo "==> FFmpeg executable not found. Running build.sh..."
#     ./build.sh  # TODO: Check if this does what we want or just generate artefacts.
# fi

echo "==> Changing to FFmpeg source directory: $FFMPEG_SRC_DIR"
cd "$FFMPEG_SRC_DIR"

if [ "$1" == "list" ]; then
    echo "==> Listing all FATE tests..."
    make fate-list

elif [ -z "$1" ]; then
    echo "==> Running all FATE tests..."
    make fate

else
    echo "==> Running FATE test(s) matching '$1'..."
    make "fate-$1"
fi

echo "==> Test run finished successfully."
