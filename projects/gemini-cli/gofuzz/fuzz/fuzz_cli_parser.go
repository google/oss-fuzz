package fuzz

import "strings"

// FuzzCLIParser fuzzes command-line argument parsing logic.
func FuzzCLIParser(data []byte) int {
	// Skip empty or huge inputs (keep runs fast/deterministic).
	if len(data) == 0 || len(data) > 1<<20 { // 1 MiB cap
		return 0
	}
	args := parseArgs(string(data))

	// Structural signal only: parsed some bounded argv → interesting.
	if len(args) > 0 && len(args) <= 100 {
		return 1
	}
	return 0
}

// parseArgs simulates CLI-style tokenization with quotes/escapes.
func parseArgs(input string) []string {
	var args []string
	var current strings.Builder
	inQuotes := false
	escape := false
	quoteChar := rune(0)

	for _, r := range input {
		if escape {
			current.WriteRune(r)
			escape = false
			continue
		}
		if r == '\\' {
			escape = true
			continue
		}
		if inQuotes {
			if r == quoteChar {
				inQuotes = false
			} else {
				current.WriteRune(r)
			}
			continue
		}
		if r == '"' || r == '\'' {
			inQuotes = true
			quoteChar = r
			continue
		}
		if r == ' ' || r == '\t' || r == '\n' || r == '\r' {
			if current.Len() > 0 {
				args = append(args, current.String())
				current.Reset()
			}
			continue
		}
		current.WriteRune(r)
	}

	if current.Len() > 0 {
		args = append(args, current.String())
	}
	return args
}
