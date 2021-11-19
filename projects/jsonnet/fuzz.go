package jsonnet

func Fuzz(data []byte) int {
	vm := MakeVM()

	_, _ = vm.EvaluateAnonymousSnippet("example1.jsonnet", string(data))
	return 1
}
