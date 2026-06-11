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

package ast_test

import (
	"testing"
	"github.com/open-policy-agent/opa/ast"
)

func FuzzParseModule(f *testing.F) {
	f.Add("package test\n\np = true\n")
	f.Add("")
	f.Add("package x\n\np { input.user == \"admin\" }\n")
	f.Fuzz(func(t *testing.T, input string) {
		if len(input) > 1<<16 { return }
		func() {
			defer func() { recover() }()
			ast.MustParseModule(input)
		}()
	})
}

func FuzzParseBody(f *testing.F) {
	f.Add("x = 1; y = 2")
	f.Add("true")
	f.Fuzz(func(t *testing.T, input string) {
		if len(input) > 1<<16 { return }
		func() {
			defer func() { recover() }()
			ast.MustParseBody(input)
		}()
	})
}

func FuzzParseExpr(f *testing.F) {
	f.Add("x > 0")
	f.Add("contains(data.users, input.user)")
	f.Add("")
	f.Fuzz(func(t *testing.T, input string) {
		if len(input) > 1<<16 { return }
		func() {
			defer func() { recover() }()
			ast.MustParseExpr(input)
		}()
	})
}

func FuzzParseStatements(f *testing.F) {
	f.Add("package test\n\nallow = true")
	f.Add("import data.rbac\n\nallow { rbac.allow }")
	f.Fuzz(func(t *testing.T, input string) {
		if len(input) > 1<<16 { return }
		func() {
			defer func() { recover() }()
			ast.MustParseStatements(input)
		}()
	})
}

func FuzzParseImports(f *testing.F) {
	f.Add("data.rbac")
	f.Add("future.keywords.contains")
	f.Add("")
	f.Fuzz(func(t *testing.T, input string) {
		if len(input) > 1<<16 { return }
		func() {
			defer func() { recover() }()
			ast.MustParseImports(input)
		}()
	})
}
