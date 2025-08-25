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
Object.defineProperty(exports, "__esModule", { value: true });
exports.sourceCodeCoverage = void 0;
const istanbul_lib_instrument_1 = require("istanbul-lib-instrument");
function sourceCodeCoverage(filename, opts = {}) {
    return ({ types }) => {
        const ee = (0, istanbul_lib_instrument_1.programVisitor)(types, filename, opts);
        return {
            visitor: {
                Program: {
                    enter: ee.enter,
                    exit(path) {
                        ee.exit(path);
                    },
                },
            },
        };
    };
}
exports.sourceCodeCoverage = sourceCodeCoverage;
//# sourceMappingURL=sourceCodeCoverage.js.map