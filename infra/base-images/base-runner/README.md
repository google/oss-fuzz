# base-runner
> Base image for fuzzer runners.

```bash
docker run -ti gcr.io/oss-fuzz-base/base-runner <command> <args>
```

## Commands

| Command | Description |
|---------|-------------|
| `reproduce <fuzzer_name> <fuzzer_options>` | build all fuzz targets and run specified one with testcase `/testcase` and given options.
| `run_fuzzer <fuzzer_name> <fuzzer_options>` | runs specified fuzzer combining options with `.options` file |
| `test_all.py` | runs every binary in `/out` as a fuzzer for a while to ensure it works. |
| `coverage <fuzzer_name>` | generate a coverage report for the given fuzzer. |

# Examples

- *Reproduce using latest OSS-Fuzz build:*

<pre>
docker run --rm -ti -v <b><i>&lt;testcase_path&gt;</i></b>:/testcase gcr.io/oss-fuzz/<b><i>$PROJECT_NAME</i></b> reproduce <b><i>&lt;fuzzer_name&gt;</i></b>
</pre>

- *Reproduce using local source checkout:*

<pre>
docker run --rm -ti -v <b><i>&lt;source_path&gt;</i></b>:/src/<b><i>$PROJECT_NAME</i></b> \
                    -v <b><i>&lt;testcase_path&gt;</i></b>:/testcase gcr.io/oss-fuzz/<b><i>$PROJECT_NAME</i></b> \
                    reproduce <b><i>&lt;fuzzer_name&gt;</i></b>
</pre>
