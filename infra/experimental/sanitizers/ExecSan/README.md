# Shell Injection Detection with `ptrace`

We use `ptrace` to instrument system calls made by the target program to detect if our `sand` command was injected into the *shell* of the target `oyster` program and executed by the program to produce of a `pearl` file.
Our instrumentation verifies the existence of `/tmp/pearl` after every `execve` or each process spawned via `clone`, which proves the existence of shell injection vulnerabilities.

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


## TODOs
1. Trace the `execve` syscalls of child processes of the target, not the `clone` and
   `wait4` of the target
2. Flag syntax errors of shell commands, as they are suspicious even without
   seeing the proof of error

