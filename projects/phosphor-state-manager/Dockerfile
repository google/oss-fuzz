FROM gcr.io/oss-fuzz-base/base-builder
RUN apt-get update && apt-get install -y make autoconf automake libtool nlohmann-json3-dev zip

RUN git clone --depth 1 https://github.com/openbmc/phosphor-state-manager.git phosphor-state-manager
WORKDIR phosphor-state-manager
COPY build.sh $SRC/
COPY target_parser_fuzzer.cpp $SRC/
COPY target_parser_fuzzer.dict $SRC/
COPY mock_includes $SRC/mock_includes
