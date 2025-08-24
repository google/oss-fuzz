"use strict";
/*
 * Copyright 2023 Code Intelligence GmbH
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.prepareArgs = exports.ensureFilepath = exports.importModule = void 0;
const path_1 = __importDefault(require("path"));
const process_1 = __importDefault(require("process"));
async function importModule(name) {
    return import(name);
}
exports.importModule = importModule;
function ensureFilepath(filePath) {
    if (!filePath || filePath.length === 0) {
        throw Error("Empty filepath provided");
    }
    const absolutePath = path_1.default.isAbsolute(filePath)
        ? filePath
        : path_1.default.join(process_1.default.cwd(), filePath);
    // file: schema is required on Windows
    const fullPath = "file://" + absolutePath;
    return [".js", ".mjs", ".cjs"].some((suffix) => fullPath.endsWith(suffix))
        ? fullPath
        : fullPath + ".js";
}
exports.ensureFilepath = ensureFilepath;
/**
 * Transform arguments to common format, add compound properties and
 * remove framework specific ones, so that the result can be passed on to the
 * regular option handling code.
 *
 * The function is extracted to "utils" as importing "cli" in tests directly
 * tries to parse command line arguments.
 */
// eslint-disable-next-line @typescript-eslint/no-explicit-any
function prepareArgs(args) {
    const options = {
        ...args,
        fuzz_target: ensureFilepath(args.fuzz_target),
        fuzzer_options: (args.corpus ?? [])
            .concat(args._)
            .map((e) => e + ""),
    };
    delete options._;
    delete options.corpus;
    delete options.$0;
    return options;
}
exports.prepareArgs = prepareArgs;
//# sourceMappingURL=utils.js.map