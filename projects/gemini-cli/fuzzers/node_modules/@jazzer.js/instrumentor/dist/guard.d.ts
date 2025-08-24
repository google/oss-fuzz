export declare class InstrumentationGuard {
    private map;
    /**
     * Add a tag and a value to the guard. This can be used to look up if the value.
     * The value will be stringified internally before being added to the guard.
     * @example instrumentationGuard.add("AssignmentExpression", node.left);
     */
    add(tag: string, value: unknown): void;
    /**
     * Check if a value with a given tag exists in the guard. The value will be stringified internally before being checked.
     * @example instrumentationGuard.has("AssignmentExpression", node.object);
     */
    has(expression: string, value: unknown): boolean;
}
export declare const instrumentationGuard: InstrumentationGuard;
