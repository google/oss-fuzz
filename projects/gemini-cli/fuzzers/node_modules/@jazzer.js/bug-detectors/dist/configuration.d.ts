export declare function getBugDetectorConfiguration(bugDetector: string): unknown;
declare class BugDetectorConfigurations {
    configurations: Map<string, any>;
    set(bugDetector: string, configuration: any): void;
    get(bugDetector: string): any;
}
export declare const bugDetectorConfigurations: BugDetectorConfigurations;
export {};
