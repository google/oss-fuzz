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
exports.bugDetectorConfigurations = exports.getBugDetectorConfiguration = void 0;
// User-facing API
function getBugDetectorConfiguration(bugDetector) {
    return exports.bugDetectorConfigurations.get(bugDetector);
}
exports.getBugDetectorConfiguration = getBugDetectorConfiguration;
class BugDetectorConfigurations {
    // eslint-disable-next-line  @typescript-eslint/no-explicit-any
    configurations = new Map();
    // eslint-disable-next-line  @typescript-eslint/no-explicit-any
    set(bugDetector, configuration) {
        this.configurations.set(bugDetector, configuration);
    }
    // eslint-disable-next-line  @typescript-eslint/no-explicit-any
    get(bugDetector) {
        return this.configurations.get(bugDetector);
    }
}
exports.bugDetectorConfigurations = new BugDetectorConfigurations();
//# sourceMappingURL=configuration.js.map