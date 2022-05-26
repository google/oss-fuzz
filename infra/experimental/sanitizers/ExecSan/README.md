# Shell Injection Detection with `ptrace`

We use `ptrace` to instrument system calls made by the target program to detect if our `/tmp/tripwire` command in `vuln.dict` was injected into the shell of the testing target program and executed by the program to produce of a `/tmp/injected` file.
Our instrumentation verifies the existence of `/tmp/injected` after every `execve` or each process spawned via `clone`, which proves the existence of shell injection vulnerabilities.

## Quick test

### Cleanup
Note this will delete /tmp/tripwire and /tmp/injected if they exist
```shell
make clean
```

### Run test
Note this will overwrite /tmp/tripwire and /tmp/injected if they exist
```shell
make test
```

Look for the following line:

> ===BUG DETECTED: Shell injection===

which indicates the detection of shell injections


## TODOs
1. Trace the `execve` syscalls in child processes of the target, not the `clone`
   and `wait4` in the target;
2. Flag syntax errors of shell commands, as they are suspicious enough even without
   seeing the proof of error (i.e. `/tmp/injected`);
3. Suffix the injected file with the corresponding PID (e.g. `/tmp/injected_{PID}`).

