package cel

// Create environment for running under Address sanitizer without timing out.
func getCELFuzzEnv() (*Env, error) {
	// Very dense expressions (balanced trees) can cause address sanitizer to
	// timeout even though they typically fail in under a second uninstrumented.
	return NewEnv(ParserRecursionLimit(60))
}
