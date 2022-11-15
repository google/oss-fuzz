FROM gcr.io/oss-fuzz-base/base-builder-python:v1
COPY . $SRC/oss-fuzz
WORKDIR oss-fuzz
COPY .clusterfuzzlite/build.sh $SRC/
RUN cp .clusterfuzzlite/coverage_atheris_fuzzer.py infra
WORKDIR infra/
RUN pip3 install --upgrade pip
RUN pip3 install -r cifuzz/requirements.txt
RUN cp -r cifuzz/* .

