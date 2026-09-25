// Copyright 2021 Google LLC
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

package cel

import (
	"google.golang.org/protobuf/proto"

	"cel.dev/cel-go/checker/decls"
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
