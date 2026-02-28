FROM gcr.io/oss-fuzz-base/base-builder-python

RUN pip3 install atheris

RUN git clone --depth 1 https://github.com/olaflaitinen/citysense.git /src/citysense
WORKDIR /src/citysense

RUN pip3 install .

COPY build.sh $SRC/
