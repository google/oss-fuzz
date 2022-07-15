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


## PoC in Python with `pytorch-lightning`
With `execSan`, [`Artheris`](https://github.com/google/atheris) can detect a shell injection bug in [version v1.5.10 of `pytorch-lightning`](https://github.com/PyTorchLightning/pytorch-lightning/tree/1.5.0).
```shell
make pytorch-lightning-1.5.10
```

## PoC in JavaScript with `shell-quote`
With `execSan`, [`Jsfuzz`](https://gitlab.com/gitlab-org/security-products/analyzers/fuzzers/jsfuzz) can detect a shell corrpution bug in [the latest version (v1.7.3) of `shell-quote`](https://github.com/substack/node-shell-quote) without any seed.
```shell
make node-shell-quote-v1.7.3
```
This is based on [a shell injection exploit report](https://wh0.github.io/2021/10/28/shell-quote-rce-exploiting.html) of [version v1.7.2 of `shell-quote`](https://github.com/substack/node-shell-quote/tree/v1.7.2).
`execSan` can also discover the same shell injection bug with a corpus file containing:
```
`:`/tmp/tripwire``:`
```


## TODOs
1. Find real examples of past shell injection vulnerabilities using this.
2. More specific patterns of error messages (to avoid false postives/negatives)
  * e.g. cache and concatenate the buffer of consecutive `write` syscalls
  * e.g. define the RegEx of patterns and pattern-match with buffers

