# OSS-Fuzz project Dockerfile for blamejs — a Node framework with
# security-on-by-default posture. See project.yaml for primary
# contact + upstream homepage.

FROM gcr.io/oss-fuzz-base/base-builder-javascript

# Clone the framework. ClusterFuzz tracks main on every run; pin a
# specific tag instead of -b main to freeze the surface.
RUN git clone --depth 1 -b main https://github.com/blamejs/blamejs $SRC/blamejs

WORKDIR $SRC/blamejs

COPY build.sh $SRC/
