// Copyright 2026 Google LLC
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

// FuzzMacros targets comprehension macros (all, exists, filter, map)
// and optional field selection which are not covered by FuzzCompile or FuzzEval.
func FuzzMacros(data []byte) int {
	if len(data) < 2 {
		return 0
	}

	macroType := int(data[0]) % 6
	expr := string(data[1:])

	var fullExpr string
	switch macroType {
	case 0:
		fullExpr = "[1,2,3,4,5].all(x, " + expr + ")"
	case 1:
		fullExpr = "[1,2,3,4,5].exists(x, " + expr + ")"
	case 2:
		fullExpr = "[1,2,3,4,5].filter(x, " + expr + ")"
	case 3:
		fullExpr = "[1,2,3,4,5].map(x, " + expr + ")"
	case 4:
		fullExpr = "[1,2,3,4,5].exists_one(x, " + expr + ")"
	case 5:
		fullExpr = expr
	}

	env, err := getCELFuzzEnv()
	if err != nil {
		return 0
	}

	env, err = env.Extend(
		Variable("x", IntType),
		Variable("s", StringType),
		Variable("items", ListType(IntType)),
	)
	if err != nil {
		return 0
	}

	ast, iss := env.Parse(fullExpr)
	if iss != nil && iss.Err() != nil {
		return 0
	}

	checked, iss := env.Check(ast)
	if iss != nil && iss.Err() != nil {
		return 0
	}

	prg, err := env.Program(checked)
	if err != nil {
		return 0
	}

	prg.Eval(map[string]any{
		"x":     int64(3),
		"s":     "test",
		"items": []int64{1, 2, 3, 4, 5},
	})

	return 1
}
