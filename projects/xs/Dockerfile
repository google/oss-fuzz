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

# install npm tool to strip comments
ENV DEBIAN_FRONTEND=noninteractive
RUN apt update && apt install -yqq npm 
# && rm -rf /var/lib/apt/lists/*
RUN npm i -g @prasadrajandran/strip-comments-cli

#test262 built-ins
#BSD license
RUN git clone --depth 1 https://github.com/tc39/test262 && \
    # strip comments
    find test262/test/built-ins -iname '*.js' -exec stripcomments --write --confirm-overwrite '{}' \+ && \
    # strip empty lines
    find test262/test/built-ins -iname '*.js' -exec sed -i '/^[[:space:]]*$/d' '{}' \+ && \
    find test262/test/built-ins -iname '*.js' | zip -@ -q $SRC/xst_seed_corpus.zip

RUN git clone --depth=1 https://github.com/Moddable-OpenSource/moddable moddable && \
    # strip comments
    find moddable/tests/xs -iname '*.js' -exec stripcomments --write --confirm-overwrite '{}' \+ && \
    # strip empty lines
    find moddable/tests/xs -iname '*.js' -exec sed -i '/^[[:space:]]*$/d' '{}' \+ && \
    find moddable/tests/xs -iname '*.js' | zip -@ -q $SRC/xst_seed_corpus.zip
WORKDIR $SRC/moddable

COPY build.sh xst.options $SRC/

# clean up
RUN npm rm @prasadrajandran/strip-comments-cli && apt purge -yqq npm && apt autoremove -yqq && rm -rf /var/lib/apt/lists/*
