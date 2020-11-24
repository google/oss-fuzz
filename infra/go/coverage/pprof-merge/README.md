# pprof-merge

Merges multiple pprof profile files into one.

## Installation

```
$ go get github.com/rakyll/pprof-merge
```

## Usage

```
$ pprof-merge profile1.data profile2.data ...
$ pprof merged.data
```

Note: pprof already can work with multiple
profile files. Example:

```
$ pprof profile1.data profile2.data ...
```

pprof-merge helps you to merge profiles in
case you want to store them merged.