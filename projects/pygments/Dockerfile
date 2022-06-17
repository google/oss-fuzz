# Copyright 2019 Google Inc.
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

FROM gcr.io/oss-fuzz-base/base-builder-python

RUN git clone \
	--depth 1 \
	--branch master \
	https://github.com/pygments/pygments.git

WORKDIR pygments

RUN git clone --depth 1 https://github.com/google/fuzzing
RUN cat fuzzing/dictionaries/aff.dict \
        fuzzing/dictionaries/bash.dict \
        fuzzing/dictionaries/creole.dict \
        fuzzing/dictionaries/css.dict \
        fuzzing/dictionaries/graphviz.dict \
        fuzzing/dictionaries/fbs.dict \
        fuzzing/dictionaries/html.dict \
        fuzzing/dictionaries/jinja2.dict \
        fuzzing/dictionaries/js.dict \
        fuzzing/dictionaries/json.dict \
        fuzzing/dictionaries/lua.dict \
        fuzzing/dictionaries/markdown.dict \
        fuzzing/dictionaries/mathml.dict \
        fuzzing/dictionaries/pdf.dict \
        fuzzing/dictionaries/protobuf.dict \
        fuzzing/dictionaries/ps.dict \
        fuzzing/dictionaries/regexp.dict \
        fuzzing/dictionaries/rst.dict \
        fuzzing/dictionaries/rtf.dict \
        fuzzing/dictionaries/sql.dict \
        fuzzing/dictionaries/svg.dict \
        fuzzing/dictionaries/tex.dict \
        fuzzing/dictionaries/toml.dict \
        fuzzing/dictionaries/utf8.dict \
        fuzzing/dictionaries/vcf.dict \
        fuzzing/dictionaries/wkt.dict \
        fuzzing/dictionaries/x86.dict \
        fuzzing/dictionaries/xml.dict \
        fuzzing/dictionaries/xpath.dict \
        fuzzing/dictionaries/xslt.dict \
        fuzzing/dictionaries/yaml.dict \
        fuzzing/dictionaries/yara.dict \
      > $OUT/pygments_fuzzer.dict

COPY build.sh fuzz_guesser.py fuzz_lexers.py $SRC/
