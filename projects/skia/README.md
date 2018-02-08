When bench testing image_filter_deserialize, it may be useful to have malloc_limit_mb = 500, and timeout = 10 to find actionable OOM culprits sooner.

When reproducing, instead of running
python infra/helper.py reproduce ... try running

docker run --rm -i --privileged -v $OSS_DIR/build/out/skia:/out -v [/path/to/testcase]:/testcase -t gcr.io/oss-fuzz-base/base-runner reproduce image_filter_deserialize -runs=100 -malloc_limit_mb=100

So the OOM can be better located.