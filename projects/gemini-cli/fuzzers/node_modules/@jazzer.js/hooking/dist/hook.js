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
exports.Hook = exports.HookType = void 0;
/* eslint @typescript-eslint/no-explicit-any: 0 */
var HookType;
(function (HookType) {
    HookType[HookType["Before"] = 0] = "Before";
    HookType[HookType["After"] = 1] = "After";
    HookType[HookType["Replace"] = 2] = "Replace";
})(HookType || (exports.HookType = HookType = {}));
class Hook {
    type;
    target;
    pkg;
    async;
    hookFunction;
    constructor(type, target, pkg, async, hookFunction) {
        this.type = type;
        this.target = target;
        this.pkg = pkg;
        this.async = async;
        this.hookFunction = hookFunction;
    }
    match(pkg, target) {
        return pkg.includes(this.pkg) && target == this.target;
    }
}
exports.Hook = Hook;
//# sourceMappingURL=hook.js.map