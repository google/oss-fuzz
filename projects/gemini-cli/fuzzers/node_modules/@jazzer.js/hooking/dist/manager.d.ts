import { Hook, HookFn, HookType } from "./hook";
export declare class MatchingHooksResult {
    private _beforeHooks;
    private _replaceHooks;
    private _afterHooks;
    get hooks(): Hook[];
    hasHooks(): boolean;
    get beforeHooks(): Hook[];
    hasBeforeHooks(): boolean;
    get replaceHooks(): Hook[];
    hasReplaceHooks(): boolean;
    get afterHooks(): Hook[];
    hasAfterHooks(): boolean;
    addHook(h: Hook): void;
    verify(): void;
}
export declare class HookManager {
    private _hooks;
    /**
     * Finalizes the registration of new hooks and performs necessary
     * initialization steps for the hooks to work. This method must be called
     * after all hooks have been registered.
     */
    finalizeHooks(): Promise<void>;
    registerHook(hookType: HookType, target: string, pkg: string, async: boolean, hookFn: HookFn): Hook;
    get hooks(): Hook[];
    clearHooks(): void;
    hookIndex(hook: Hook): number;
    matchingHooks(target: string, filepath: string): MatchingHooksResult;
    hasFunctionsToHook(filepath: string): boolean;
    callHook(id: number, thisPtr: object, params: unknown[], resultOrOriginalFunction: unknown): unknown;
}
export declare const hookManager: HookManager;
export declare function registerBeforeHook(target: string, pkg: string, async: boolean, hookFn: HookFn): void;
export declare function registerReplaceHook(target: string, pkg: string, async: boolean, hookFn: HookFn): void;
export declare function registerAfterHook(target: string, pkg: string, async: boolean, hookFn: HookFn): void;
/**
 * Replaces a built-in function with a custom implementation while preserving
 * the original function for potential use within the replacement function.
 */
export declare function hookBuiltInFunction(hook: Hook): Promise<void>;
/**
 * Returns a unique id for the call site of the function that called this function.
 * @param additionalArguments additional arguments to be included in the hash
 */
export declare function callSiteId(...additionalArguments: unknown[]): number;
