package cel

import (
	"github.com/golang/protobuf/proto"

	"github.com/google/cel-go/checker/decls"
)

func FuzzEval(data []byte) int {
	gen := &FuzzVariables{}
	err := proto.Unmarshal(data, gen)
	if err != nil {
		panic("Failed to unmarshal LPM generated variables")
	}

	env, err := NewEnv()
	if err != nil {
		panic("impossible to create env")
	}
	for k, _ := range gen.Inputs {
		env, err = env.Extend(Declarations(decls.NewVar(k, decls.String)))
		if err != nil {
			panic("impossible to extend env")
		}
	}

	ast, issues := env.Compile(gen.Expr)
	if issues != nil && issues.Err() != nil {
		return 0
	}
	prg, err := env.Program(ast)
	if err != nil {
		panic("impossible to create prog from ast")
	}
	//fmt.Printf("loltry %#+v\n", gen)

	_, _, err = prg.Eval(gen.Inputs)

	return 1
}
