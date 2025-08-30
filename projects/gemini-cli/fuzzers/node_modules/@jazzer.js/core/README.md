# @jazzer.js/core

This is the main entry point and all most users have to install as a
dev-dependency, so that they can fuzz their projects.

The `@jazzer.js/core` module provide a CLI interface via the `jazzer` command.
It can be used by `npx` or node script command. To display a command
documentation use the `--help` flag.

```shell
npx jazzer --help
```

The `core` module also provides the function `startFuzzing(options: Options)`as
entry point for further integrations and external tools.

## Install

Using npm:

```sh
npm install --save-dev @jazzer.js/core
```

## Documentation

See
[Jazzer.js README](https://github.com/CodeIntelligenceTesting/jazzer.js#readme)
for more information or the
[issues](https://github.com/CodeIntelligenceTesting/jazzer.js/issues?q=is%3Aissue+is%3Aopen)
associated with it.
