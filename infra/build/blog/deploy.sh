#!/bin/bash -ex
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

docker build -t oss-fuzz-blog .

rm -rf site
mkdir -p site

docker build -t oss-fuzz-blog .
docker run --rm -ti -v $(pwd)/site:/site oss-fuzz-blog sh -c 'cp -r /oss-fuzz-blog/page/public /site && chmod -R 777 /site'

gsutil -h "Cache-Control:no-cache,max-age=0" -m cp -r site/public/* gs://oss-fuzz-blog
