---
layout: default
title: Integrating a JavaScript project
parent: Setting up a new project
grand_parent: Getting started
nav_order: 4
permalink: /getting-started/new-project-guide/javascript-lang/
---

# Integrating a JavaScript project
{: .no_toc}

- TOC
{:toc}
---

The process of integrating a project written in JavaScript for Node.js 
with OSS-Fuzz is very similar to the general
[Setting up a new project]({{ site.baseurl }}/getting-started/new-project-guide/)
process. The key specifics of integrating a JavaScript project are outlined below.

## Jazzer.js

JavaScript fuzzing in OSS-Fuzz is powered by
[Jazzer.js](https://github.com/CodeIntelligenceTesting/jazzer.js), which is
installed during the build step. As Jazzer.js operates directly on the JavaScript
source code level, it can be applied to any project written in a language that 
can be transpiled into JavaScript such as TypeScript. More information on how Jazzer.js
fuzz targets look like can be found in its
[README's Usage section](https://github.com/CodeIntelligenceTesting/jazzer.js#usage).

## Project files

### Example project

We recommend viewing
[javascript-example](https://github.com/google/oss-fuzz/tree/master/projects/javascript-example)
as an example of a simple JavaScript fuzzing project. We also recommend having a look at
[typescript-example](https://github.com/google/oss-fuzz/tree/master/projects/typescript-example)
as an example of how to fuzz TypeScript projects. This example also demonstrates how to use 
Jazzer.js fuzzed data provider.

### project.yaml

The `language` attribute must be specified as follows:

```yaml
language: javascript
```

The only supported fuzzing engine is libFuzzer (`libfuzzer`). So far, native sanitizers such as 
AddressSanitizer (`address`) and UndefinedBehaviorSanitizer (`undefined`) are not supported. 
They would only be needed for projects that have native addons, which is a rather infrequent
use case for JavaScript projects. If you have a project where you need ASan or UBSan, please 
create open an issue on [Jazzer.js GitHub repo](https://github.com/CodeIntelligenceTesting/jazzer.js). None (`none`) is the default sanitizer for 
JavaScript projects, so setting it up in `project.yaml` is optional.

```yaml
fuzzing_engines:
  - libfuzzer
sanitizers:
  - none
```

### Dockerfile

The Dockerfile should start by `FROM gcr.io/oss-fuzz-base/base-builder-javascript`

The OSS-Fuzz base Docker images already come with Node.js 19 and `npm` pre-installed.
Apart from that, you should usually not need to do more than to clone the
project, set a `WORKDIR`, and copy any necessary files, or install any
project-specific dependencies here as you normally would.

### Fuzzers

In the simplest case, every fuzzer consists of a single JavaScript file that exports
a function named `fuzz` taking a single argument of type [Buffer](https://nodejs.org/api/buffer.html). 
An example fuzz target could thus be a file `fuzz_string_compare.js` with contents:

```javascript
/**
 * @param { Buffer } data
 */
module.exports.fuzz = function (data) {
    const s = data.toString();
    if (s.length !== 16) {
        return;
    }
    if (
        s.slice(0, 8) === "Awesome " &&
        s.slice(8, 15) === "Fuzzing" &&
        s[15] === "!"
    ) {
        throw Error("Welcome to Awesome Fuzzing!");
    }
};
```

### build.sh

The OSS-Fuzz base docker image for JavaScript comes with the [`compile_javascript_fuzzer` script](https://github.com/google/oss-fuzz/blob/master/infra/base-images/base-builder/compile_javascript_fuzzer) preinstalled. In `build.sh`, you should install dependencies for your project, and if necessary compile the code into JavaScript. Then, you can use the script to build the fuzzers. The script ensures that [@Jazzer.js/core](https://www.npmjs.com/package/@jazzer.js/core) is installed so that its CLI can be used to execute your fuzz tests. It also generates a wrapper script that can be used as a drop-in replacement for libFuzzer. This means that the generated script accepts the same command line flags for libFuzzer. Under the hood these flags are simply forwarded to the libFuzzer native addon used by Jazzer.js.

A usage example from the javascript-example project is

```shell
compile_javascript_fuzzer example fuzz_string_compare.js --sync
```

Arguments are:
* relative path of the project in the $SRC directory
* relative path to the fuzz test inside the project
* remaining arguments are forwarded to the [Jazzer.js CLI](https://github.com/CodeIntelligenceTesting/jazzer.js/blob/main/docs/fuzz-targets.md#running-the-fuzz-target)

The [javascript-example](https://github.com/google/oss-fuzz/blob/master/projects/javascript-example/build.sh)
project contains an example of a `build.sh` for JavaScript projects.

## FuzzedDataProvider

Jazzer.js provides a `FuzzedDataProvider` that can simplify the task of creating a
fuzz target by translating the raw input bytes received from the fuzzer into
useful primitive JavaScript types. Its functionality is similar to
`FuzzedDataProviders` available in other languages, such as
[Java](https://codeintelligencetesting.github.io/jazzer-docs/jazzer-api/com/code_intelligence/jazzer/api/FuzzedDataProvider.html) and
[C++](https://github.com/google/fuzzing/blob/master/docs/split-inputs.md).

A fuzz target using the `FuzzedDataProvider` would look as follows:

```javascript
const { FuzzedDataProvider } = require("@jazzer.js/core");

/**
 * @param { Buffer } fuzzerInputData
 */
module.exports.fuzz = function (fuzzerInputData) {
    const data = new FuzzedDataProvider(fuzzerInputData);
    const i = data.consumeIntegral(4);
    const s = data.consumeRemainingAsString();
    exploreMe(i, s);
};
```
