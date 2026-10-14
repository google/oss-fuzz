# Seed Corpus for alembic_getarchive_vector_fuzzer

This directory contains seed inputs for the Alembic getArchive vector fuzzer.

## Input Format

The fuzzer expects input in the following format:
```
[4-byte little-endian length][file data][4-byte length][file data]...
```

## Corpus Files

- `sample1.bin`: Single 10-byte file
- `sample2.bin`: Two 5-byte files ("Hello", "World")  
- `sample3.bin`: Four 1-byte files ("A", "B", "C", "D")

## Adding New Seeds

To add new seed files:
1. Create test data following the format above
2. Add meaningful Alembic file content when possible
3. Place files in this directory
4. The fuzzer will use them as starting points for mutation
