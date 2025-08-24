package fuzz

import (
	"github.com/google-gemini/gemini-cli/gofuzz/internal"
)

// FuzzSlashCommands tests .toml slash command parsing logic
func FuzzSlashCommands(data []byte) int {
	if len(data) == 0 {
		return 0
	}

	parser := internal.NewSlashCommandParser()

	// Test TOML parsing with the input
	err := parser.ParseTOMLSlashCommand(string(data))
	if err != nil {
		// Expected error for malformed input, continue fuzzing
		return 0
	}

	// If parsing succeeds, we found valid input
	return 1
}

// FuzzToolInvocation tests dangerous tool invocation patterns
func FuzzToolInvocation(data []byte) int {
	if len(data) == 0 {
		return 0
	}

	simulator := internal.NewToolInvocationSimulator()

	// Split input into tool name and parameters
	input := string(data)
	if len(input) < 2 {
		return 0
	}

	// First byte determines tool, rest is input
	toolIndex := int(data[0]) % 4
	toolName := ""
	switch toolIndex {
	case 0:
		toolName = "google_search"
	case 1:
		toolName = "file_system"
	case 2:
		toolName = "shell_execute"
	case 3:
		toolName = "web_fetch"
	}

	toolInput := input[1:]

	err := simulator.SimulateToolInvocation(toolName, toolInput)
	if err != nil {
		// Expected error for dangerous input, continue fuzzing
		return 0
	}

	// If no error, we found potentially dangerous but valid input
	return 1
}

// FuzzTypeScriptBridge tests the TypeScript bridge components
func FuzzTypeScriptBridge(data []byte) int {
	if len(data) == 0 {
		return 0
	}

	// Split data for different tests
	half := len(data) / 2

	// Test CLI parsing
	cliParser := internal.NewCLIParser()
	_, err := cliParser.ParseCLI(string(data[:half]))
	if err != nil {
		return 0
	}

	// Test config parsing
	configParser := internal.NewConfigParser()
	err = configParser.ParseConfig(string(data[half:]))
	if err != nil {
		return 0
	}

	// Test MCP parsing
	mcpParser := internal.NewMCPParser()
	err = mcpParser.ParseMCPRequest(string(data))
	if err != nil {
		return 0
	}

	return 1
}
