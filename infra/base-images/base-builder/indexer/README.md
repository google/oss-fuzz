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
```

The resulting snapshots will be found in `<oss-fuzz checkout>/build/out/<project>`.

## Development

For faster local development on the scripts in this directory, we can mount in
these scripts to overwrite the previous versions.

```
export PROJECT_NAME=<project>
export OSS_FUZZ_CHECKOUT=<path to your oss-fuzz checkout>
cd $OSS_FUZZ_CHECKOUT/infra/base-images/base-builder/indexer

# One time setup steps
curl -o indexer https://clusterfuzz-builds.storage.googleapis.com/oss-fuzz-artifacts/indexer-59fad4ca5b1047c6afa2f60d754bd6ae1fa08c34
chmod +x indexer

cd $OSS_FUZZ_CHECKOUT
python infra/helper.py build_image $PROJECT_NAME

docker run --rm -ti -e PROJECT_NAME=$PROJECT_NAME \
    -v $OSS_FUZZ_CHECKOUT/infra/base-images/base-builder/indexer:/opt/indexer \
    -v $OSS_FUZZ_CHECKOUT/build/out/$PROJECT_NAME:/out \
    gcr.io/oss-fuzz/$PROJECT_NAME /bin/bash

python /opt/indexer/index_build.py
# To only build snapshots for `target1` and `target2`:
# python /opt/indexer/index_build.py --targets target1,target2
```

The resulting snapshots will be found in `<oss-fuzz checkout>/build/out/<project>`.

## Testing

We have some basic tests to make sure the snapshots we're generating have the correct format.

```
sudo INDEX_BUILD_TESTS=1 python3 -m unittest index_build_test
```