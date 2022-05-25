# Shell Injection Detection with `ptrace`

## Quick test

### Cleanup
Note this will delete /tmp/bomb and /tmp/bombfile if they exist
```shell
make clean
```

### Run test
Note this will overwrite /tmp/bomb and /tmp/bombfile if they exist
```shell
make test
```

This should end with the following line:

> ===BUG DETECTED: Shell injection===

which indicates the detection of shell injection
