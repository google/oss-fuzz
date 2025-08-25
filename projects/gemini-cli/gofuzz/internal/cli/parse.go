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

package cli

import (
	"errors"
	"fmt"
	"strings"
)

// Minimal CLI argument parser mirror for fuzzing shell injection vectors.
// Based on common CLI patterns without actual execution.

type Command struct {
	Name    string
	Args    []string
	Flags   map[string]string
	Options map[string]bool
}

type ParseResult struct {
	Command   *Command
	Remaining []string
}

// ParseArgs mirrors CLI argument parsing logic for fuzzing.
// Focuses on injection-prone areas without actual execution.
func ParseArgs(args []string) (*ParseResult, error) {
	if len(args) == 0 {
		return nil, errors.New("no arguments provided")
	}

	// Prevent excessively long argument lists
	if len(args) > 1000 {
		return nil, errors.New("too many arguments")
	}

	cmd := &Command{
		Name:    args[0],
		Args:    []string{},
		Flags:   make(map[string]string),
		Options: make(map[string]bool),
	}

	// Basic validation of command name
	if err := validateCommandName(cmd.Name); err != nil {
		return nil, err
	}

	i := 1
	for i < len(args) {
		arg := args[i]
		
		// Prevent excessively long individual arguments
		if len(arg) > 4096 {
			return nil, errors.New("argument too long")
		}

		if strings.HasPrefix(arg, "--") {
			// Long flag
			if err := parseLongFlag(arg, args, &i, cmd); err != nil {
				return nil, err
			}
		} else if strings.HasPrefix(arg, "-") && len(arg) > 1 {
			// Short flag
			if err := parseShortFlag(arg, cmd); err != nil {
				return nil, err
			}
		} else {
			// Regular argument
			cmd.Args = append(cmd.Args, arg)
		}
		i++
	}

	return &ParseResult{
		Command:   cmd,
		Remaining: []string{},
	}, nil
}

func validateCommandName(name string) error {
	if len(name) == 0 {
		return errors.New("empty command name")
	}
	if len(name) > 256 {
		return errors.New("command name too long")
	}
	
	// Check for shell injection patterns
	dangerous := []string{";", "&", "|", "`", "$", "(", ")", "<", ">", "&&", "||"}
	for _, pattern := range dangerous {
		if strings.Contains(name, pattern) {
			return fmt.Errorf("potentially dangerous pattern in command: %s", pattern)
		}
	}
	
	return nil
}

func parseLongFlag(arg string, args []string, i *int, cmd *Command) error {
	parts := strings.SplitN(arg[2:], "=", 2)
	flagName := parts[0]
	
	if len(flagName) == 0 {
		return errors.New("empty flag name")
	}
	
	if len(parts) == 2 {
		// --flag=value
		cmd.Flags[flagName] = parts[1]
	} else {
		// --flag (boolean or next arg is value)
		if *i+1 < len(args) && !strings.HasPrefix(args[*i+1], "-") {
			*i++
			cmd.Flags[flagName] = args[*i]
		} else {
			cmd.Options[flagName] = true
		}
	}
	
	return nil
}

func parseShortFlag(arg string, cmd *Command) error {
	flags := arg[1:] // Remove leading -
	
	for _, flag := range flags {
		flagStr := string(flag)
		cmd.Options[flagStr] = true
	}
	
	return nil
}