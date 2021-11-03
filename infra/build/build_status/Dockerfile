FROM gcr.io/oss-fuzz-base/base-runner


RUN mkdir -p /opt/oss-fuzz/infra/build_status
COPY ${OSS_FUZZ_ROOT}/infra/functions/* /opt/oss-fuzz/infra/build_status/
COPY ${OSS_FUZZ_ROOT}/infra/build_status/* /opt/oss-fuzz/infra/build_status/
RUN pip install -r /opt/oss-fuzz/infra/build_status/requirements.txt
ENTRYPOINT [ "python3", "/opt/oss-fuzz/infra/build_status/update_build_status.py" ]