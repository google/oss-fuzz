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

BASE=$PWD

# Build the site
mkdir oss-fuzz-blog
cd oss-fuzz-blog

hugo new site page
cd page
git init
git submodule add https://github.com/luizdepra/hugo-coder.git themes/hugo-coder

# Copy over our content
cp $BASE/hugo.toml .
rm -rf ./content
cp -rf $BASE/content .

# Build the site
hugo -D

# Uncomment the following to launch site automatically
#python3 -m http.server 8011 -d ./oss-fuzz-blog/page/public
