import * as fuzzer from "@jazzer.js/fuzzer";
export interface FuzzModule {
    [fuzzEntryPoint: string]: fuzzer.FuzzTarget;
}
export declare function importModule(name: string): Promise<FuzzModule | void>;
export declare function ensureFilepath(filePath: string): string;
/**
 * Transform arguments to common format, add compound properties and
 * remove framework specific ones, so that the result can be passed on to the
 * regular option handling code.
 *
 * The function is extracted to "utils" as importing "cli" in tests directly
 * tries to parse command line arguments.
 */
export declare function prepareArgs(args: any): any;
