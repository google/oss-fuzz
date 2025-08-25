import { PluginTarget } from "@babel/core";
/**
 * Instrumentation plugins are can be used to add additional instrumentation by
 * bug detectors.
 */
export declare class InstrumentationPlugins {
    private _plugins;
    registerPlugin(plugin: () => PluginTarget): void;
    get plugins(): (() => PluginTarget)[];
}
export declare const instrumentationPlugins: InstrumentationPlugins;
export declare function registerInstrumentationPlugin(plugin: () => PluginTarget): void;
