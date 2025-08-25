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
exports.logHooks = exports.hookTracker = void 0;
const hook_1 = require("./hook");
/**
 * Stores package names and names of functions of interest (targets) from that
 * package  [packageName0 -> [target0, ...], ...].
 *
 * This structure is used to keep track of all functions seen during
 * instrumentation and execution of the fuzzing run, to determine which hooks
 * have been applied, are available, and have not been applied.
 */
class HookTable {
    _hooks = new Map();
    add(pkg, target) {
        if (!this._hooks.has(pkg)) {
            this._hooks.set(pkg, new Set());
        }
        this._hooks.get(pkg)?.add(target);
    }
    has(pkg, target) {
        if (!this._hooks.has(pkg)) {
            return false;
        }
        return this._hooks.get(pkg)?.has(target);
    }
    clear() {
        this._hooks.clear();
    }
    get length() {
        let size = 0;
        for (const targets of this._hooks.values()) {
            size += targets.size;
        }
        return size;
    }
    serialize() {
        const result = [];
        for (const [pkg, targets] of [...this._hooks].sort()) {
            for (const target of [...targets].sort()) {
                result.push({ pkg: pkg, target: target });
            }
        }
        return result;
    }
}
/**
 * HookTracker keeps track of hooks that were applied, are available, and were
 * not applied.
 *
 * This is helpful when debugging custom hooks and bug detectors.
 */
class HookTracker {
    _applied = new HookTable();
    _available = new HookTable();
    _notApplied = new HookTable();
    print() {
        console.error("DEBUG: [Hook] Summary:");
        console.error("DEBUG: [Hook]    Not applied: " + this._notApplied.length);
        this._notApplied.serialize().forEach((hook) => {
            console.error(`DEBUG: [Hook] not applied: ${hook.pkg} -> ${hook.target}`);
        });
        console.error("DEBUG: [Hook]    Applied: " + this._applied.length);
        this._applied.serialize().forEach((hook) => {
            console.error(`DEBUG: [Hook] applied:     ${hook.pkg} -> ${hook.target}`);
        });
        console.error("DEBUG: [Hook]    Available: " + this._available.length);
        this._available.serialize().forEach((hook) => {
            console.error(`DEBUG: [Hook] available:   ${hook.pkg} -> ${hook.target}`);
        });
    }
    categorizeUnknown(requestedHooks) {
        requestedHooks.forEach((hook) => {
            if (!this._applied.has(hook.pkg, hook.target) &&
                !this._available.has(hook.pkg, hook.target)) {
                this.addNotApplied(hook.pkg, hook.target);
            }
        });
        return this;
    }
    clear() {
        this._applied.clear();
        this._notApplied.clear();
        this._available.clear();
    }
    addApplied(pkg, target) {
        this._applied.add(pkg, target);
    }
    addAvailable(pkg, target) {
        this._available.add(pkg, target);
    }
    addNotApplied(pkg, target) {
        this._notApplied.add(pkg, target);
    }
    get applied() {
        return this._applied.serialize();
    }
    get available() {
        return this._available.serialize();
    }
    get notApplied() {
        return this._notApplied.serialize();
    }
}
exports.hookTracker = new HookTracker();
function logHooks(hooks) {
    hooks.forEach((hook) => {
        if (process.env.JAZZER_DEBUG) {
            console.error(`DEBUG: Applied %s-hook in %s#%s`, hook_1.HookType[hook.type], hook.pkg, hook.target);
        }
    });
}
exports.logHooks = logHooks;
//# sourceMappingURL=tracker.js.map