# Indexer snapshot builds

This directory provides the tooling to be able to build "indexed" OSS-Fuzz
builds, which are snapshots which provide the binary, source code, and a source
code index.

Snapshots are also built by our infrastructure and available at
`gs://clusterfuzz-builds/indexer_indexes`.

## Building project snapshots

```bash
python infra/helper.py build_image <project>
python infra/helper.py index <project>

# Only build snapshots for `target1` and `target2`.
python infra/helper.py index --targets 'target1,target2' <project>

# Drop into /bin/bash instead of automatically running /opt/indexer/index_build.py.
python infra/helper.py index --shell <project>

# Add additional docker args.
python infra/helper.py index --docker_arg="-eFOO=123" --docker_arg="-eBAR=456" <project>

# Pass through flags to the entrypoint.
python infra/helper.py index <project> -- --target-args '123'
```

The resulting snapshots will be found in `<oss-fuzz checkout>/build/out/<project>`.

## Development

For faster local development on the scripts in this directory, we can mount in
these scripts to overwrite the previous versions.

```
export PROJECT_NAME=<project>
export OSS_FUZZ_CHECKOUT=<path to your oss-fuzz checkout>
cd $OSS_FUZZ_CHECKOUT/infra/base-images/base-builder/indexer

# One time setup step to get a copy of the indexer binary.
curl -o indexer https://clusterfuzz-builds.storage.googleapis.com/oss-fuzz-artifacts/indexer-59fad4ca5b1047c6afa2f60d754bd6ae1fa08c34
chmod +x indexer

cd $OSS_FUZZ_CHECKOUT
python infra/helper.py index $PROJECT_NAME \
    --docker_arg="--volume=$OSS_FUZZ_CHECKOUT/infra/base-images/base-builder/indexer:/opt/indexer"
```

The resulting snapshots will be found in `<oss-fuzz checkout>/build/out/<project>`.

## Testing

We have some basic tests to make sure the snapshots we're generating have the correct format.

```
sudo INDEX_BUILD_TESTS=1 python3 -m unittest index_build_test
```
