#!/bin/bash
PROJECT=$1
FUZZ_TARGET=$2
FUZZING_LANGUAGE=$3

gcloud builds submit "https://github.com/google/oss-fuzz" \
  --git-source-revision=master \
  --config=cloudbuild.yaml \
  --substitutions=_PROJECT=$PROJECT,_FUZZ_TARGET=$FUZZ_TARGET,_FUZZING_LANGUAGE=$FUZZING_LANGUAGE
