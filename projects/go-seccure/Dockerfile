# OSS-Fuzz build container for go-seccure. Lives here for review/onboarding;
# the active copy is in google/oss-fuzz's projects/go-seccure/ directory.

FROM gcr.io/oss-fuzz-base/base-builder-go

RUN git clone --depth 1 https://github.com/invenity-labs/go-seccure $SRC/go-seccure
WORKDIR $SRC/go-seccure

COPY build.sh $SRC/
