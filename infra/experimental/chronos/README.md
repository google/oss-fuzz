# Chronos: rebuilding OSS-Fuzz harnesses using cached builds

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
