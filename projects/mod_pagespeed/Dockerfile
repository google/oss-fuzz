FROM gcr.io/oss-fuzz-base/base-builder
# gperf generates the HTML, CSS and bot-name lookup tables during the build.
# The apt lists stay: the introspector build installs packages of its own.
RUN apt-get update && apt-get install -y --no-install-recommends gperf
RUN git clone --depth 1 https://github.com/We-Amp/mod_pagespeed.git mod_pagespeed
WORKDIR $SRC/mod_pagespeed
COPY build.sh $SRC/
