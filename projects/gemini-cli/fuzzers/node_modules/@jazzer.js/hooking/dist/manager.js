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
exports.callSiteId = exports.hookBuiltInFunction = exports.registerAfterHook = exports.registerReplaceHook = exports.registerBeforeHook = exports.hookManager = exports.HookManager = exports.MatchingHooksResult = void 0;
const module_1 = require("module");
const hook_1 = require("./hook");
const tracker_1 = require("./tracker");
class MatchingHooksResult {
    _beforeHooks = [];
    _replaceHooks = [];
    _afterHooks = [];
    get hooks() {
        return this._beforeHooks.concat(this._afterHooks, this._replaceHooks);
    }
    hasHooks() {
        return (this.hasBeforeHooks() || this.hasReplaceHooks() || this.hasAfterHooks());
    }
    get beforeHooks() {
        return this._beforeHooks;
    }
    hasBeforeHooks() {
        return this._beforeHooks.length !== 0;
    }
    get replaceHooks() {
        return this._replaceHooks;
    }
    hasReplaceHooks() {
        return this._replaceHooks.length !== 0;
    }
    get afterHooks() {
        return this._afterHooks;
    }
    hasAfterHooks() {
        return this._afterHooks.length !== 0;
    }
    addHook(h) {
        switch (h.type) {
            case hook_1.HookType.Before:
                this._beforeHooks.push(h);
                break;
            case hook_1.HookType.Replace:
                this._replaceHooks.push(h);
                break;
            case hook_1.HookType.After:
                this._afterHooks.push(h);
                break;
        }
    }
    verify() {
        if (this._replaceHooks.length > 1) {
            throw new Error(`For a given target function, one REPLACE hook can be configured. Found: ${this._replaceHooks.length}`);
        }
        if (this.hasReplaceHooks() &&
            (this.hasBeforeHooks() || this.hasAfterHooks())) {
            throw new Error(`For a given target function, REPLACE hooks cannot be mixed up with BEFORE/AFTER hooks. Found ${this._replaceHooks.length} REPLACE hooks and ${this._beforeHooks.length + this._afterHooks.length} BEFORE/AFTER hooks`);
        }
        if (this.hasAfterHooks()) {
            if (!this._afterHooks.every((h) => h.async) &&
                !this._afterHooks.every((h) => !h.async)) {
                throw new Error("For a given target function, AFTER hooks have to be either all sync or all async.");
            }
        }
    }
}
exports.MatchingHooksResult = MatchingHooksResult;
class HookManager {
    _hooks = [];
    /**
     * Finalizes the registration of new hooks and performs necessary
     * initialization steps for the hooks to work. This method must be called
     * after all hooks have been registered.
     */
    async finalizeHooks() {
        // Built-in functions cannot be hooked by the instrumentor, so that is
        // explicitly done here instead.
        // Loading build-in modules is asynchronous, so we need to wait, which
        // is not possible in the instrumentor.
        for (const builtinModule of module_1.builtinModules) {
            const matchedHooks = this._hooks.filter((hook) => builtinModule.includes(hook.pkg));
            for (const hook of matchedHooks) {
                try {
                    await hookBuiltInFunction(hook);
                }
                catch (e) {
                    if (process.env.JAZZER_DEBUG) {
                        console.error("DEBUG: [Hook] Error when trying to hook the built-in function: " +
                            e);
                    }
                }
            }
        }
    }
    registerHook(hookType, target, pkg, async, hookFn) {
        const hook = new hook_1.Hook(hookType, target, pkg, async, hookFn);
        this._hooks.push(hook);
        return hook;
    }
    get hooks() {
        return this._hooks;
    }
    clearHooks() {
        this._hooks = [];
    }
    hookIndex(hook) {
        return this._hooks.indexOf(hook);
    }
    matchingHooks(target, filepath) {
        const matches = this._hooks
            .filter((hook) => hook.match(filepath, target))
            .reduce((matches, hook) => {
            matches.addHook(hook);
            return matches;
        }, new MatchingHooksResult());
        matches.verify();
        return matches;
    }
    hasFunctionsToHook(filepath) {
        return (this._hooks.find((hook) => filepath.includes(hook.pkg)) !== undefined);
    }
    callHook(id, thisPtr, params, resultOrOriginalFunction) {
        const hook = this._hooks[id];
        switch (hook.type) {
            case hook_1.HookType.Before:
                hook.hookFunction(thisPtr, params, callSiteId());
                break;
            case hook_1.HookType.Replace:
                return hook.hookFunction(thisPtr, params, callSiteId(), 
                // eslint-disable-next-line @typescript-eslint/ban-types
                resultOrOriginalFunction);
            case hook_1.HookType.After:
                hook.hookFunction(thisPtr, params, callSiteId(), resultOrOriginalFunction);
        }
    }
}
exports.HookManager = HookManager;
exports.hookManager = new HookManager();
function registerBeforeHook(target, pkg, async, hookFn) {
    exports.hookManager.registerHook(hook_1.HookType.Before, target, pkg, async, hookFn);
}
exports.registerBeforeHook = registerBeforeHook;
function registerReplaceHook(target, pkg, async, hookFn) {
    exports.hookManager.registerHook(hook_1.HookType.Replace, target, pkg, async, hookFn);
}
exports.registerReplaceHook = registerReplaceHook;
function registerAfterHook(target, pkg, async, hookFn) {
    exports.hookManager.registerHook(hook_1.HookType.After, target, pkg, async, hookFn);
}
exports.registerAfterHook = registerAfterHook;
/**
 * Replaces a built-in function with a custom implementation while preserving
 * the original function for potential use within the replacement function.
 */
async function hookBuiltInFunction(hook) {
    const { default: module } = await import(hook.pkg);
    const originalFn = module[hook.target];
    const id = callSiteId(exports.hookManager.hookIndex(hook), hook.pkg, hook.target);
    if (hook.type == hook_1.HookType.Before) {
        module[hook.target] = (...args) => {
            hook.hookFunction(null, args, id);
            return originalFn(...args);
        };
    }
    else if (hook.type == hook_1.HookType.Replace) {
        module[hook.target] = (...args) => {
            return hook.hookFunction(null, args, id, originalFn);
        };
    }
    else if (hook.type == hook_1.HookType.After) {
        module[hook.target] = (...args) => {
            const result = originalFn(...args);
            return hook.hookFunction(null, args, id, result);
        };
    }
    else {
        throw new Error(`Unknown hook type ${hook.type}`);
    }
    (0, tracker_1.logHooks)([hook]);
    tracker_1.hookTracker.addApplied(hook.pkg, hook.target);
}
exports.hookBuiltInFunction = hookBuiltInFunction;
/**
 * Returns a unique id for the call site of the function that called this function.
 * @param additionalArguments additional arguments to be included in the hash
 */
function callSiteId(...additionalArguments) {
    const stackTrace = additionalArguments?.join(",") + new Error().stack;
    if (!stackTrace || stackTrace.length === 0) {
        return 0;
    }
    let hash = 0, i, chr;
    for (i = 0; i < stackTrace.length; i++) {
        chr = stackTrace.charCodeAt(i);
        hash = (hash << 5) - hash + chr;
        hash |= 0; // Convert to 32bit integer
    }
    return hash;
}
exports.callSiteId = callSiteId;
//# sourceMappingURL=manager.js.map