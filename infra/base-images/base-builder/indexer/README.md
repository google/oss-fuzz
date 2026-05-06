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
everything inside this directory to overwrite the scripts in the base image by
passing `--dev` to the index command.

If the `indexer` binary does not exist, a prebuilt binary is
[downloaded](https://clusterfuzz-builds.storage.googleapis.com/oss-fuzz-artifacts/indexer).

```
cd $OSS_FUZZ_CHECKOUT
python infra/helper.py index --dev <PROJECT_NAME>
```

The resulting snapshots will be found in `<oss-fuzz checkout>/build/out/<project>`.

## Testing

We have some basic tests to make sure the snapshots we're generating have the correct format.

For this to work, you need to run `python infra/helper.py index --dev <PROJECT_NAME>` at least
once, or make sure you have the `indexer` binary in this directory.

```
sudo INDEX_BUILD_TESTS=1 python3 -m unittest index_build_test
```
