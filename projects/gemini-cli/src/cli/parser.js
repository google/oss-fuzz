// Copyright 2025 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

/**
 * CLI Argument Parser for gemini-cli
 * This is the actual code that will be fuzzed
 */

class CLIParser {
    constructor() {
        this.commands = new Map();
        this.options = new Map();
    }

    parseCliArgs(args) {
        if (!Array.isArray(args)) {
            throw new TypeError('Arguments must be an array');
        }

        const result = {
            command: null,
            options: {},
            positionals: []
        };

        let i = 0;
        while (i < args.length) {
            const arg = args[i];

            if (typeof arg !== 'string') {
                throw new TypeError('All arguments must be strings');
            }

            // Handle long options --option
            if (arg.startsWith('--')) {
                const [key, value] = arg.slice(2).split('=');
                result.options[key] = value || true;
            }
            // Handle short options -o
            else if (arg.startsWith('-') && arg.length > 1) {
                const key = arg.slice(1);
                // Next arg might be the value
                if (i + 1 < args.length && !args[i + 1].startsWith('-')) {
                    result.options[key] = args[++i];
                } else {
                    result.options[key] = true;
                }
            }
            // Handle commands and positionals
            else {
                if (!result.command && this.commands.has(arg)) {
                    result.command = arg;
                } else {
                    result.positionals.push(arg);
                }
            }
            i++;
        }

        return result;
    }

    validateCommand(command, options) {
        // Validation logic that could have bugs
        if (!command) {
            throw new Error('Command is required');
        }

        if (command.length > 100) {
            throw new Error('Command name too long');
        }

        // Check for injection attempts
        if (command.includes('..') || command.includes('/') || command.includes('\\\\')) {
            throw new Error('Invalid command characters');
        }

        return true;
    }

    registerCommand(name, handler) {
        this.commands.set(name, handler);
    }
}

// Export for use in fuzzers
const parser = new CLIParser();

// Register some default commands
parser.registerCommand('init', () => {});
parser.registerCommand('run', () => {});
parser.registerCommand('test', () => {});
parser.registerCommand('build', () => {});

module.exports = {
    parseCliArgs: (args) => parser.parseCliArgs(args),
    validateCommand: (cmd, opts) => parser.validateCommand(cmd, opts),
    CLIParser
};
