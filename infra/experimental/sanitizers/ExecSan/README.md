# Shell Injection Detection with `ptrace`

We use `ptrace` to instrument system calls made by the target program to detect if our `sand` command was injected into the *shell* of the target `oyster` program during execution and led to the production of a `pearl` file.
Our instrumentation verifies the existence of `/tmp/pearl` after every `execve` and each `wait4` after `clone`, which proves the existence of shell injection vulnerabilities.

## Quick test

### Cleanup
Note this will delete /tmp/sand and /tmp/pearl if they exist
```shell
make clean
```

### Run test
Note this will overwrite /tmp/sand and /tmp/pearl if they exist
```shell
make harvest
```

This should end with the following line:

> ===BUG DETECTED: Shell injection===

which indicates the detection of shell injections
