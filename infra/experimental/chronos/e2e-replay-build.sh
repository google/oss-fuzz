#!/usr/bin/bash
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

# Sample projects: simd, wt, libheif, htslib
PROJECT=liblouis
LOG=replay-${PROJECT}.txt
OUT1=replay-out-${PROJECT}-1
OUT2=replay-out-${PROJECT}-2
python infra/helper.py build_image --no-pull  "$PROJECT"

# AddressSanitizer.
mkdir -p build/out/${PROJECT}
echo "start" >> ${LOG}
echo $(date +%Y:%m:%d:%H:%M:%S) >> ${LOG}
# Remove container name we are about to use.
docker container rm "${PROJECT}-origin-asan"

# Build once, clean container if needed
docker run -v $PWD/build/out/${PROJECT}:/out \
    -ti --entrypoint="/bin/sh" \
    --env FUZZING_LANGUAGE=c  --env SANITIZER="address" \
    --name "${PROJECT}-origin-asan" \
    "gcr.io/oss-fuzz/${PROJECT}" -c "compile"

# Copy outs and log data
cp -rf $PWD/build/out/${PROJECT} ${OUT1}
rm -rf $PWD/build/out/${PROJECT}
ls -la $PWD/build/out/ >> ${LOG}
echo "next" >> ${LOG}
echo $(date +%Y:%m:%d:%H:%M:%S) >> ${LOG}
docker commit "${PROJECT}-origin-asan" "gcr.io/oss-fuzz/${PROJECT}-ofg-cached-asan"

# Run the replay command
docker run -v $PWD/build/out/${PROJECT}:/out \
    -e REPLAY_ENABLED=1 -ti --entrypoint="/bin/sh" \
    --env FUZZING_LANGUAGE=c --env SANITIZER="address" \
    "gcr.io/oss-fuzz/${PROJECT}-ofg-cached-asan" -c "compile"
echo "finish" >> ${LOG}
echo $(date +%Y:%m:%d:%H:%M:%S) >> ${LOG}
cp -rf $PWD/build/out/${PROJECT} ${OUT2}

# Now match the artifacts
SUCCESS=$(infra/experimental/chronos/match_artifacts $OUT1 $OUT2)

if [[ $SUCCESS -eq 0 ]]; then
  echo "SUCCESS REPLAY" >> ${LOG}
else
  echo "FAIL REPLAY" >> ${LOG}
fi
