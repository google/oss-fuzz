FROM gcr.io/oss-fuzz-base/base-builder-java

# Install Gradle (wrapper usable too, but install for convenience)
RUN apt-get update && apt-get install -y curl unzip && rm -rf /var/lib/apt/lists/*

# Copy OkHttp source and fuzz module into image at /src/okhttp
# In OSS-Fuzz production, the infra clones the main repo based on project.yaml.
# For local testing you can COPY your fork or let build.sh fetch it.
WORKDIR /src/okhttp

# Copy build scripts and fuzzers (adjust if you vendor fuzz module in the repo)
COPY build.sh /src/okhttp/build.sh
COPY fuzz /src/okhttp/fuzz

ENV MAVEN_OPTS=-Xmx2g

RUN chmod +x /src/okhttp/build.sh

