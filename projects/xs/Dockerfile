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

FROM gcr.io/oss-fuzz-base/base-builder

#Apache-2.0 license
RUN git clone --depth 1 https://github.com/dvyukov/go-fuzz-corpus && \
    zip -q $SRC/xst_jsonparse_seed_corpus.zip go-fuzz-corpus/json/corpus/*

#Apache-2.0 license
RUN git clone --depth 1 https://github.com/google/fuzzing && \
    cat fuzzing/dictionaries/json.dict > $SRC/xst_jsonparse.dict && \
    cat fuzzing/dictionaries/js.dict > $SRC/xst.dict

#Apache-2.0 license, MIT license, BSD license
RUN git clone --depth 1 https://github.com/tc39/test262-parser-tests && \
	zip -q $SRC/xst_seed_corpus.zip test262-parser-tests/pass-explicit/*

RUN git clone --depth=1 https://github.com/Moddable-OpenSource/moddable moddable
WORKDIR moddable

COPY target.c build.sh xst.options $SRC/
