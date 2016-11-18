# base-runner
> Base image for fuzzer runners.

```bash
docker run -ti ossfuzz/base-runner <command> <args>
```

## Commands

| Command | Description |
|---------|-------------|
| `run_fuzzer <fuzzer_name> <fuzzer_options>` | runs specified fuzzer combining options with `.options` file |
| `test_all` | runs every binary in `/out` as a fuzzer for a while to ensure it works. |

