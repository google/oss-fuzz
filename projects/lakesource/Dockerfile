# LakeSource E2 libFuzzer harness - OSS-Fuzz project image.
#
# Upstream (google/oss-fuzz projects/lakesource): the infra clones main_repo
# (https://github.com/Cisne-047/lakesource) into $SRC/lakesource, which is
# why WORKDIR is $SRC/lakesource. The docker build context is the project
# directory only (Dockerfile + build.sh + project.yaml), never the engine
# tree. Do not RUN git clone. Do not COPY the engine tree.
# Local helper.py sessions (tools/fuzz/run_oss_fuzz_local.*) bind-mount the
# local checkout over the same WORKDIR; the file serves both lanes.

FROM gcr.io/oss-fuzz-base/base-builder

COPY build.sh $SRC/
WORKDIR $SRC/lakesource
