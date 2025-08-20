import { addon } from "./addon";
/**
 * Performs a string comparison between two strings and calls the corresponding native hook if needed.
 * This function replaces the original comparison expression and preserves the semantics by returning
 * the original result after calling the native hook.
 * @param s1 first compared string. s1 has the type `unknown` because we can only know the type at runtime.
 * @param s2 second compared string. s2 has the type `unknown` because we can only know the type at runtime.
 * @param operator the operator used in the comparison
 * @param id an unique identifier to distinguish between the different comparisons
 * @returns result of the comparison
 */
declare function traceStrCmp(s1: unknown, s2: unknown, operator: string, id: number): boolean;
/**
 * Performs an integer comparison between two strings and calls the corresponding native hook if needed.
 * This function replaces the original comparison expression and preserves the semantics by returning
 * the original result after calling the native hook.
 * @param n1 first compared number
 * @param n2 second compared number
 * @param operator the operator used in the comparison
 * @param id an unique identifier to distinguish between the different comparisons
 * @returns result of the comparison
 */
declare function traceNumberCmp(n1: number, n2: number, operator: string, id: number): boolean;
declare function traceAndReturn(current: unknown, target: unknown, id: number): unknown;
export interface Tracer {
    traceStrCmp: typeof traceStrCmp;
    traceUnequalStrings: typeof addon.traceUnequalStrings;
    traceStringContainment: typeof addon.traceStringContainment;
    traceNumberCmp: typeof traceNumberCmp;
    traceAndReturn: typeof traceAndReturn;
    tracePcIndir: typeof addon.tracePcIndir;
    guideTowardsEquality: typeof guideTowardsEquality;
    guideTowardsContainment: typeof guideTowardsContainment;
    exploreState: typeof exploreState;
}
export declare const tracer: Tracer;
/**
 * Instructs the fuzzer to guide its mutations towards making `current` equal to `target`
 *
 * If the relation between the raw fuzzer input and the value of `current` is relatively
 * complex, running the fuzzer with the argument `-use_value_profile=1` may be necessary to
 * achieve equality.
 *
 * @param current a non-constant string observed during fuzz target execution
 * @param target a string that `current` should become equal to, but currently isn't
 * @param id a (probabilistically) unique identifier for this particular compare hint
 */
declare function guideTowardsEquality(current: string, target: string, id: number): void;
/**
 * Instructs the fuzzer to guide its mutations towards making `haystack` contain `needle` as a substring.
 *
 * If the relation between the raw fuzzer input and the value of `haystack` is relatively
 * complex, running the fuzzer with the argument `-use_value_profile=1` may be necessary to
 * satisfy the substring check.
 *
 * @param needle a string that should be contained in `haystack` as a substring, but
 *     currently isn't
 * @param haystack a non-constant string observed during fuzz target execution
 * @param id a (probabilistically) unique identifier for this particular compare hint
 */
declare function guideTowardsContainment(needle: string, haystack: string, id: number): void;
/**
 * Instructs the fuzzer to attain as many possible values for the absolute value of `state`
 * as possible.
 *
 * Call this function from a fuzz target or a hook to help the fuzzer track partial progress
 * (e.g. by passing the length of a common prefix of two lists that should become equal) or
 * explore different values of state that is not directly related to code coverage.
 *
 * Note: This hint only takes effect if the fuzzer is run with the argument
 * `-use_value_profile=1`.
 *
 * @param state a numeric encoding of a state that should be varied by the fuzzer
 * @param id a (probabilistically) unique identifier for this particular state hint
 */
export declare function exploreState(state: number, id: number): void;
export {};
