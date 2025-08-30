export interface EdgeIdStrategy {
    nextEdgeId(): number;
    startForSourceFile(filename: string): void;
    commitIdCount(filename: string): void;
}
export declare abstract class IncrementingEdgeIdStrategy implements EdgeIdStrategy {
    protected _nextEdgeId: number;
    protected constructor(_nextEdgeId: number);
    nextEdgeId(): number;
    abstract startForSourceFile(filename: string): void;
    abstract commitIdCount(filename: string): void;
}
export declare class MemorySyncIdStrategy extends IncrementingEdgeIdStrategy {
    constructor();
    startForSourceFile(filename: string): void;
    commitIdCount(filename: string): void;
}
/**
 * A strategy for edge ID generation that synchronizes the IDs assigned to a source file
 * with other processes via the specified `idSyncFile`. The edge information stored as a
 * line of the format: <source file path>,<initial edge ID>,<total edge count>
 *
 * This class takes care of synchronizing the access to the file between
 * multiple processes accessing it during instrumentation.
 */
export declare class FileSyncIdStrategy extends IncrementingEdgeIdStrategy {
    private idSyncFile;
    private static readonly fatalExitCode;
    private cachedIdCount;
    private firstEdgeId;
    private releaseLockOnSyncFile;
    constructor(idSyncFile: string);
    startForSourceFile(filename: string): void;
    commitIdCount(filename: string): void;
    private wait;
    private randomIntFromInterval;
    private isLockAlreadyHeldError;
}
export declare class ZeroEdgeIdStrategy implements EdgeIdStrategy {
    nextEdgeId(): number;
    startForSourceFile(filename: string): void;
    commitIdCount(filename: string): void;
}
