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
