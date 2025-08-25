import { RawSourceMap } from "source-map";
export interface SourceMaps {
    [file: string]: SourceMap | undefined;
}
export type SourceMap = {
    version: number;
    sources: string[];
    names: string[];
    sourceRoot?: string | undefined;
    sourcesContent?: string[] | undefined;
    mappings: string;
    file: string;
};
/**
 * Extracts the inline source map from a code string.
 *
 * Inline source maps can be added to the end of a code file during offline
 * and online transpilation. Babel transformers or the TypeScript compiler
 * are examples of this.
 */
export declare function extractInlineSourceMap(code: string): SourceMap | undefined;
export declare function toRawSourceMap(sourceMap?: SourceMap): RawSourceMap | undefined;
export declare class SourceMapRegistry {
    private sourceMaps;
    registerSourceMap(filename: string, sourceMap: SourceMap): void;
    getSourceMap(filename: string): SourceMap | undefined;
    installSourceMapSupport(): () => void;
}
