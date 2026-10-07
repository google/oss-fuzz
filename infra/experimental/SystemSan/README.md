# System Sanitizers

We use `ptrace` to instrument system calls made by the target program to detect
various vulnerabilities.

## Command injection

This detector currently works by

- Checking if `execve` is called with `/tmp/tripwire` (which comes from our dictionary).
- Checking if `execve` is invoking a shell with invalid syntax. This is likely
  caused by our input.

## Arbitrary file open

TODO: documentation.

## Proof of concept

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


### Command injection PoC in Python with `pytorch-lightning`
With `SystemSan`, [`Artheris`](https://github.com/google/atheris) can detect a shell injection bug in [version v1.5.10 of `pytorch-lightning`](https://github.com/PyTorchLightning/pytorch-lightning/tree/1.5.0).
```shell
make pytorch-lightning-1.5.10
```

### Command injection PoC in JavaScript with `shell-quote`
With `SystemSan`, [`Jsfuzz`](https://gitlab.com/gitlab-org/security-products/analyzers/fuzzers/jsfuzz) can detect a shell corrpution bug in [the latest version (v1.7.3) of `shell-quote`](https://github.com/substack/node-shell-quote) without any seed.
```shell
make node-shell-quote-v1.7.3
```
This is based on [a shell injection exploit report](https://wh0.github.io/2021/10/28/shell-quote-rce-exploiting.html) of [version v1.7.2 of `shell-quote`](https://github.com/substack/node-shell-quote/tree/v1.7.2).
`SystemSan` can also discover the same shell injection bug with a corpus file containing:
```
`:`/tmp/tripwire``:`
```

## Trophies

- <https://github.com/syoyo/tinygltf/issues/368>
- <https://github.com/substack/node-shell-quote/issues/54>


