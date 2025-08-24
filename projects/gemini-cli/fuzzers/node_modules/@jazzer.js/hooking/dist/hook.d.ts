export declare enum HookType {
    Before = 0,
    After = 1,
    Replace = 2
}
export type BeforeHookFn = (thisPtr: any, params: any[], hookId: number) => any;
export type ReplaceHookFn = (thisPtr: any, params: any[], hookId: number, origFn: Function) => any;
export type AfterHookFn = (thisPtr: any, params: any[], hookId: number, result: any) => any;
export type HookFn = BeforeHookFn | ReplaceHookFn | AfterHookFn;
export declare class Hook {
    readonly type: HookType;
    readonly target: string;
    readonly pkg: string;
    readonly async: boolean;
    readonly hookFunction: HookFn;
    constructor(type: HookType, target: string, pkg: string, async: boolean, hookFunction: HookFn);
    match(pkg: string, target: string): boolean;
}
