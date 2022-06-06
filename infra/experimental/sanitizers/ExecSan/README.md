# Shell Injection Detection with `ptrace`

We use `ptrace` to instrument system calls made by the target program to detect
if our `/tmp/tripwire` command in `vuln.dict` was injected into the shell of
the testing target program. This works by

- Checking if `execve` is called with `/tmp/tripwire`.
- TODO: Checking if we managed to invoke a shell (e.g. /bin/sh) and cause a
  syntax error.

## Quick test

### Cleanup
Note this will delete /tmp/tripwire if it exists.
```shell
make clean
```

### Run test
Note this will overwrite /tmp/tripwire if it exists.
```shell
make test
```

Look for one of the following lines:

> ===BUG DETECTED: Shell injection===

which indicates the detection of executing the planted `/tmp/tripwire`.


> ===BUG DETECTED: Shell corruption===

which indicates the detection of executing a syntactic erroneous command.


## TODOs
1. Find real examples of past shell injection vulnerabilities using this.

