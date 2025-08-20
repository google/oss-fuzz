package internal

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
)

// TypeScriptBridge provides Go implementations that mirror TypeScript Gemini CLI logic
// This allows fuzzing to target the same logic and edge cases as the actual implementation

type TypeScriptBridge struct{}

// CLIParser mirrors the TypeScript CLI parser logic
type CLIParser struct {
	commands map[string]CommandSpec
}

type CommandSpec struct {
	Name        string
	Args        []string
	Flags       map[string]interface{}
	Description string
}

// NewCLIParser creates a CLI parser that mimics TypeScript behavior
func NewCLIParser() *CLIParser {
	return &CLIParser{
		commands: map[string]CommandSpec{
			"chat": {
				Name:        "chat",
				Args:        []string{"prompt"},
				Flags:       map[string]interface{}{"model": "gemini-pro", "temperature": 0.7},
				Description: "Start a chat session",
			},
			"config": {
				Name:        "config",
				Args:        []string{"key", "value"},
				Flags:       map[string]interface{}{"list": false, "set": ""},
				Description: "Manage configuration",
			},
		},
	}
}

// ParseCLI mirrors TypeScript CLI parsing logic
func (p *CLIParser) ParseCLI(input string) (*CommandSpec, error) {
	if input == "" {
		return nil, fmt.Errorf("empty input")
	}

	parts := strings.Fields(input)
	if len(parts) == 0 {
		return nil, fmt.Errorf("no command provided")
	}

	cmdName := parts[0]
	spec, exists := p.commands[cmdName]
	if !exists {
		return nil, fmt.Errorf("unknown command: %s", cmdName)
	}

	result := spec
	args := parts[1:]

	// Parse flags and arguments (mirroring TypeScript logic)
	for i := 0; i < len(args); i++ {
		arg := args[i]
		if strings.HasPrefix(arg, "--") {
			flagName := strings.TrimPrefix(arg, "--")
			if i+1 < len(args) {
				result.Flags[flagName] = args[i+1]
				i++ // Skip next arg as it's the flag value
			} else {
				result.Flags[flagName] = true
			}
		} else if strings.HasPrefix(arg, "-") {
			// Short flags
			flagName := strings.TrimPrefix(arg, "-")
			if i+1 < len(args) {
				result.Flags[flagName] = args[i+1]
				i++ // Skip next arg
			} else {
				result.Flags[flagName] = true
			}
		} else {
			// Positional argument
			if len(result.Args) == 0 {
				result.Args = []string{arg}
			} else {
				result.Args = append(result.Args, arg)
			}
		}
	}

	return &result, nil
}

// ConfigParser mirrors TypeScript configuration parsing
type ConfigParser struct {
	config map[string]interface{}
}

// NewConfigParser creates a config parser that mimics TypeScript behavior
func NewConfigParser() *ConfigParser {
	return &ConfigParser{
		config: map[string]interface{}{
			"apiKey":     "",
			"projectId":  "",
			"theme":      map[string]interface{}{"name": "dark"},
			"proxy":      map[string]interface{}{"enabled": false},
			"memory":     map[string]interface{}{"enabled": true, "limitMb": 512},
			"tooling":    map[string]interface{}{"enableMcp": true, "enableShell": false},
			"logLevel":   "info",
			"timeout":    30,
			"maxRetries": 3,
		},
	}
}

// ParseConfig mirrors TypeScript config parsing logic
func (p *ConfigParser) ParseConfig(jsonInput string) error {
	if jsonInput == "" {
		return fmt.Errorf("empty config")
	}

	var parsed map[string]interface{}
	if err := json.Unmarshal([]byte(jsonInput), &parsed); err != nil {
		return fmt.Errorf("invalid JSON: %v", err)
	}

	// Validate against schema (mirroring TypeScript validation)
	for key, value := range parsed {
		switch key {
		case "apiKey":
			if str, ok := value.(string); !ok || len(str) == 0 {
				return fmt.Errorf("invalid apiKey")
			}
		case "timeout":
			if num, ok := value.(float64); !ok || num < 0 || num > 3600 {
				return fmt.Errorf("invalid timeout")
			}
		case "maxRetries":
			if num, ok := value.(float64); !ok || num < 0 || num > 10 {
				return fmt.Errorf("invalid maxRetries")
			}
		case "memory":
			if mem, ok := value.(map[string]interface{}); ok {
				if limit, exists := mem["limitMb"]; exists {
					if num, ok := limit.(float64); !ok || num < 0 || num > 100000 {
						return fmt.Errorf("invalid memory limit")
					}
				}
			}
		}
	}

	// Merge with existing config
	for key, value := range parsed {
		p.config[key] = value
	}

	return nil
}

// MCPParser mirrors TypeScript MCP parsing logic
type MCPParser struct{}

// NewMCPParser creates an MCP parser
func NewMCPParser() *MCPParser {
	return &MCPParser{}
}

// ParseMCPRequest mirrors TypeScript MCP request parsing
func (p *MCPParser) ParseMCPRequest(jsonInput string) error {
	if jsonInput == "" {
		return fmt.Errorf("empty MCP request")
	}

	var req map[string]interface{}
	if err := json.Unmarshal([]byte(jsonInput), &req); err != nil {
		return fmt.Errorf("invalid JSON: %v", err)
	}

	// Validate MCP request structure (mirroring TypeScript)
	if _, hasMethod := req["method"]; !hasMethod {
		return fmt.Errorf("missing method field")
	}

	if _, hasId := req["id"]; !hasId {
		return fmt.Errorf("missing id field")
	}

	method, ok := req["method"].(string)
	if !ok {
		return fmt.Errorf("invalid method type")
	}

	// Validate method format
	if !strings.Contains(method, "/") {
		return fmt.Errorf("invalid method format")
	}

	// Check for dangerous methods
	dangerousMethods := []string{"shell.execute", "file_system.write"}
	for _, dangerous := range dangerousMethods {
		if strings.Contains(method, dangerous) {
			// Additional validation for dangerous methods
			if params, hasParams := req["params"]; hasParams {
				if paramsMap, ok := params.(map[string]interface{}); ok {
					if command, hasCmd := paramsMap["command"]; hasCmd {
						if cmdStr, ok := command.(string); ok {
							// Check for dangerous command patterns
							dangerousCmds := []string{"rm -rf", "rmdir", "del", "format", "mkfs"}
							for _, dangerous := range dangerousCmds {
								if strings.Contains(cmdStr, dangerous) {
									return fmt.Errorf("dangerous command detected: %s", dangerous)
								}
							}
						}
					}
				}
			}
		}
	}

	return nil
}

// SlashCommandParser mirrors TypeScript .toml slash command parsing
type SlashCommandParser struct{}

// NewSlashCommandParser creates a slash command parser
func NewSlashCommandParser() *SlashCommandParser {
	return &SlashCommandParser{}
}

// ParseTOMLSlashCommand mirrors TypeScript .toml parsing logic
func (p *SlashCommandParser) ParseTOMLSlashCommand(tomlInput string) error {
	if tomlInput == "" {
		return fmt.Errorf("empty TOML input")
	}

	lines := strings.Split(tomlInput, "\n")
	inCommand := false
	commandName := ""

	for i, line := range lines {
		line = strings.TrimSpace(line)

		// Skip comments and empty lines
		if strings.HasPrefix(line, "#") || line == "" {
			continue
		}

		// Check for command definition
		if strings.HasPrefix(line, "[[commands]]") {
			inCommand = true
			commandName = ""
			continue
		}

		if inCommand {
			// Extract command name
			if strings.HasPrefix(line, "name = ") {
				nameMatch := regexp.MustCompile(`name\s*=\s*"([^"]+)"`)
				matches := nameMatch.FindStringSubmatch(line)
				if len(matches) > 1 {
					commandName = matches[1]
					// Validate command name format
					if !strings.HasPrefix(commandName, "/") {
						return fmt.Errorf("command name must start with /: %s", commandName)
					}
				}
			}

			// Check for template injection
			if strings.Contains(line, "{{") && strings.Contains(line, "}}") {
				return fmt.Errorf("potential template injection detected in line %d", i+1)
			}

			// Check for dangerous shell commands
			if strings.Contains(line, "shell") || strings.Contains(line, "exec") {
				dangerousPatterns := []string{"rm -rf", "rmdir", "del", "format", "sudo", "su"}
				for _, pattern := range dangerousPatterns {
					if strings.Contains(line, pattern) {
						return fmt.Errorf("dangerous shell command detected: %s", pattern)
					}
				}
			}
		}
	}

	return nil
}

// ToolInvocationSimulator simulates dangerous tool invocations
type ToolInvocationSimulator struct{}

// NewToolInvocationSimulator creates a tool invocation simulator
func NewToolInvocationSimulator() *ToolInvocationSimulator {
	return &ToolInvocationSimulator{}
}

// SimulateToolInvocation mirrors TypeScript tool invocation logic
func (s *ToolInvocationSimulator) SimulateToolInvocation(toolName, input string) error {
	if toolName == "" {
		return fmt.Errorf("empty tool name")
	}

	// Simulate different tool behaviors
	switch toolName {
	case "google_search":
		return s.simulateGoogleSearch(input)
	case "file_system":
		return s.simulateFileSystem(input)
	case "shell_execute":
		return s.simulateShellExecute(input)
	case "web_fetch":
		return s.simulateWebFetch(input)
	default:
		return fmt.Errorf("unknown tool: %s", toolName)
	}
}

func (s *ToolInvocationSimulator) simulateGoogleSearch(query string) error {
	if len(query) > 2048 {
		return fmt.Errorf("query too long")
	}
	// Check for injection patterns
	injectionPatterns := []string{"<script", "javascript:", "onload=", "onerror="}
	for _, pattern := range injectionPatterns {
		if strings.Contains(strings.ToLower(query), pattern) {
			return fmt.Errorf("XSS pattern detected in search query")
		}
	}

	return nil
}

func (s *ToolInvocationSimulator) simulateFileSystem(path string) error {
	if path == "" {
		return fmt.Errorf("empty path")
	}

	// Check for path traversal
	if strings.Contains(path, "../") || strings.Contains(path, "..\\") {
		return fmt.Errorf("path traversal detected")
	}

	// Check for dangerous paths
	dangerousPaths := []string{"/etc/passwd", "/etc/shadow", "C:\\Windows\\System32"}
	for _, dangerous := range dangerousPaths {
		if strings.Contains(path, dangerous) {
			return fmt.Errorf("access to dangerous path: %s", dangerous)
		}
	}

	return nil
}

func (s *ToolInvocationSimulator) simulateShellExecute(command string) error {
	if command == "" {
		return fmt.Errorf("empty command")
	}

	// Check for dangerous commands
	dangerousCommands := []string{
		"rm -rf /",
		"rmdir /",
		"del /",
		"format",
		"mkfs",
		"sudo su",
		"chmod +s",
		"chown root",
	}

	for _, dangerous := range dangerousCommands {
		if strings.Contains(command, dangerous) {
			return fmt.Errorf("dangerous command detected: %s", dangerous)
		}
	}

	return nil
}

func (s *ToolInvocationSimulator) simulateWebFetch(url string) error {
	if url == "" {
		return fmt.Errorf("empty URL")
	}

	// Check for dangerous protocols
	dangerousProtocols := []string{"file://", "javascript:", "data:"}
	for _, protocol := range dangerousProtocols {
		if strings.HasPrefix(strings.ToLower(url), protocol) {
			return fmt.Errorf("dangerous protocol: %s", protocol)
		}
	}

	// Check for SSRF patterns
	if strings.Contains(url, "127.0.0.1") || strings.Contains(url, "localhost") {
		return fmt.Errorf("potential SSRF detected")
	}

	return nil
}
