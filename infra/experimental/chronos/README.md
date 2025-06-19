# Chronos: rebuilding OSS-Fuzz harnesses using cached builds

## Pre-built images.

Daily pre-built images are available at:

- `us-central1-docker.pkg.dev/oss-fuzz/oss-fuzz-gen/<PROJECT>-ofg-cached-address`
- `us-central1-docker.pkg.dev/oss-fuzz/oss-fuzz-gen/<PROJECT>-ofg-cached-coverage`

They can be used as drop-in replacements for the usual `gcr.io/oss-fuzz/<PROJECT>` images.

These images are generated in 2 ways:
- (Preferred) [Generate](https://github.com/google/oss-fuzz/blob/master/infra/base-images/base-builder/bash_parser.py)
  a replay build script that can be re-run alongside existing build artifacts,
  leveraging existing build system mechanisms to avoid rebuilding (e.g. running
  `make` twice should not actually rebuild everything). This is error-prone, so
  we validate the script works by running it.
- (Fallback, if the replay build script didn't work). We leverage
  [ccache](https://ccache.dev/), to provide a compiler cache. This is often not
  as fast as the replay build script, because some project builds spend
  significant time doing non-compiler tasks (e.g. checking out submodules,
  running configure scripts).

Note: this mechanism does not work for every single OSS-Fuzz project today. The
resulting image may either:
- Not provide much performance improvement compared with a normal image, or
- Not exist at all (if neither approach worked).

Stats from a recent run: <https://gist.github.com/oliverchang/abaf3a1106a2b923c0ac3a577410aaaa>
(Feb 3 2025).

## Usage locally

**Example 1: htslib**

From the OSS-Fuzz root

```sh
$ RUN_ALL=1 ./infra/experimental/chronos/build_cache_local.sh htslib c address
...
...
Vanilla compile time:
17
Replay worked
Replay compile time:
2
Ccache compile time: 
9
```
