export declare class CoverageTracker {
    private static readonly MAX_NUM_COUNTERS;
    private static readonly INITIAL_NUM_COUNTERS;
    private readonly coverageMap;
    private currentNumCounters;
    constructor();
    enlargeCountersBufferIfNeeded(nextEdgeId: number): void;
    /**
     * Increments the coverage counter for a given ID.
     * This function implements the NeverZero policy from AFL++.
     * See https://aflplus.plus//papers/aflpp-woot2020.pdf
     * @param edgeId the edge ID of the coverage counter to increment
     */
    incrementCounter(edgeId: number): void;
    readCounter(edgeId: number): number;
}
export declare const coverageTracker: CoverageTracker;
