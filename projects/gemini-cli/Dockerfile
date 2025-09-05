FROM gcr.io/oss-fuzz-base/base-builder-javascript
RUN git clone --depth 1 https://github.com/google-gemini/gemini-cli.git
WORKDIR $SRC/gemini-cli
RUN npm ci
COPY build.sh /src/
