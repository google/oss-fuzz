FROM gcr.io/oss-fuzz-base/base-builder-jvm

RUN git clone --depth 1 https://github.com/apache/kafka

RUN cd kafka && ./gradlew jar -x test

COPY build.sh /
COPY *.java /
WORKDIR /kafka
