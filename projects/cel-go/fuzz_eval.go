package cel

import (
	"google.golang.org/protobuf/proto"

	"github.com/google/cel-go/checker/decls"
	exprpb "google.golang.org/genproto/googleapis/api/expr/v1alpha1"
)

func FuzzEval(data []byte) int {
	gen := &FuzzVariables{}
	err := proto.Unmarshal(data, gen)
	if err != nil {
		panic("Failed to unmarshal LPM generated variables")
	}

	declares := make([]*exprpb.Decl, 0, len(gen.Inputs))
	for k, _ := range gen.Inputs {
		declares = append(declares, decls.NewVar(k, decls.String))
	}
	env, err := getCELFuzzEnv()
	if err != nil {
		panic("impossible to create env")
	}

	env, err = env.Extend(Declarations(declares...))
	if err != nil {
		panic("impossible to create env")
	}

	ast, issues := env.Compile(gen.Expr)
	if issues != nil && issues.Err() != nil {
		return 0
	}
	prg, err := env.Program(ast)
	if err != nil {
		return 0
	}
	//fmt.Printf("loltry %#+v\n", gen)

	_, _, err = prg.Eval(gen.Inputs)

	return 1
}
