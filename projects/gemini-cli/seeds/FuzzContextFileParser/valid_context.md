# Project Context

## Overview
This is a sample project context file for the Gemini CLI tool.

## Configuration
- API Key: Set via `GEMINI_API_KEY` environment variable
- Theme: `dark` mode preferred
- Max tokens: 1000 for responses

## Usage Examples

### Basic Chat
```bash
echo "Hello, how are you?" | gemini-cli chat
```

### Code Completion
```bash
gemini-cli complete "function calculate_fibonacci(n):"
```

### Configuration
```bash
gemini-cli config --api-key YOUR_API_KEY --theme light
```

## Project Structure
- `src/` - Source code
- `docs/` - Documentation
- `tests/` - Test files
- `config/` - Configuration files

## Features
- Interactive chat mode
- Code completion
- Multiple output formats
- Custom themes and prompts
- History management
- Integration with external tools
