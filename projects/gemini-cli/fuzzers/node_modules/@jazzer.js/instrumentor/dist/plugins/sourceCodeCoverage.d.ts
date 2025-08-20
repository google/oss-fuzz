import { PluginTarget } from "@babel/core";
import { VisitorOptions } from "istanbul-lib-instrument";
export declare function sourceCodeCoverage(filename?: string, opts?: Partial<VisitorOptions>): PluginTarget;
