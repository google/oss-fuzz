package cel

func FuzzCompile(data []byte) int {
	env, err := getCELFuzzEnv()
	if err != nil {
		panic("impossible to create env")
	}
	ast, issues := env.Compile(string(data))
	if issues != nil && issues.Err() != nil {
		return 0
	}
	_, err = env.Program(ast)
	if err != nil {
		return 0
	}

	return 1
}
