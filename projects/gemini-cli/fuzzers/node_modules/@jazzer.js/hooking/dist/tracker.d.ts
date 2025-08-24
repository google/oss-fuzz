import { Hook } from "./hook";
export interface TrackedHook {
    target: string;
    pkg: string;
}
/**
 * HookTracker keeps track of hooks that were applied, are available, and were
 * not applied.
 *
 * This is helpful when debugging custom hooks and bug detectors.
 */
declare class HookTracker {
    private _applied;
    private _available;
    private _notApplied;
    print(): void;
    categorizeUnknown(requestedHooks: Hook[]): this;
    clear(): void;
    addApplied(pkg: string, target: string): void;
    addAvailable(pkg: string, target: string): void;
    addNotApplied(pkg: string, target: string): void;
    get applied(): TrackedHook[];
    get available(): TrackedHook[];
    get notApplied(): TrackedHook[];
}
export declare const hookTracker: HookTracker;
export declare function logHooks(hooks: Hook[]): void;
export {};
