# SPDX-License-Identifier: Apache-2.0
FROM gcr.io/oss-fuzz-base/base-builder-go

RUN git clone --depth 1 https://github.com/liqdmetal/spore

# Pin Go to the spore module's toolchain (go.mod: go 1.23.1) so the
# go-118-fuzz-build rewrites compile against the same stdlib as local runs.
RUN wget https://go.dev/dl/go1.23.12.linux-amd64.tar.gz \
&& mkdir temp-go \
&& rm -rf /root/.go/* \
&& tar -C temp-go/ -xzf go1.23.12.linux-amd64.tar.gz \
&& mv temp-go/go/* /root/.go/ \
&& rm -rf temp-go go1.23.12.linux-amd64.tar.gz

# go-118-fuzz-build (main branch) is referenced from spore's go.mod via a
# replace directive added by build.sh; the v1 flow rewrites the harness's
# `testing` import to this shim package. Pinned to the commit the targets
# were verified against.
RUN git clone https://github.com/AdamKorcz/go-118-fuzz-build $SRC/fuzzbuild \
&& git -C $SRC/fuzzbuild checkout a70c2aa677fa43583571959478decabe02a96cd6

COPY build.sh $SRC/
WORKDIR $SRC/spore
