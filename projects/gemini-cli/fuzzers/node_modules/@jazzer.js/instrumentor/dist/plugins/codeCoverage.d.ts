import { PluginTarget } from "@babel/core";
import { EdgeIdStrategy } from "../edgeIdStrategy";
export declare function codeCoverage(idStrategy: EdgeIdStrategy): () => PluginTarget;
