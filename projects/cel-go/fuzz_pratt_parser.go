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

import (
	"fmt"
	"strings"

	"cel.dev/cel-go/common"
	"cel.dev/cel-go/common/ast"
	"cel.dev/cel-go/parser"
	"google.golang.org/protobuf/proto"

	exprpb "google.golang.org/genproto/googleapis/api/expr/v1alpha1"
)

func mustCreateParser(opts ...parser.Option) *parser.Parser {
	p, err := parser.NewParser(opts...)
	if err != nil {
		panic(err)
	}
	return p
}

var (
	antlrParser = mustCreateParser(
		parser.Macros(parser.AllMacros...),
		parser.PopulateMacroCalls(true),
		parser.EnableOptionalSyntax(true),
		parser.EnableIdentEscapeSyntax(true),
		parser.MaxRecursionDepth(32),
		parser.ErrorRecoveryLimit(4),
		parser.ErrorRecoveryLookaheadTokenLimit(4),
		parser.EnablePrattParser(false),
	)

	prattParser = mustCreateParser(
		parser.Macros(parser.AllMacros...),
		parser.PopulateMacroCalls(true),
		parser.EnableOptionalSyntax(true),
		parser.EnableIdentEscapeSyntax(true),
		parser.MaxRecursionDepth(32),
		parser.ErrorRecoveryLimit(4),
		parser.ErrorRecoveryLookaheadTokenLimit(4),
		parser.EnablePrattParser(true),
	)
)

func isWordChar(c byte) bool {
	return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '_'
}

// ANTLR grammar only supports 'br' prefix order for raw byte literals (e.g., br'abc'),
// whereas Pratt parser supports both 'br' and 'rb' (e.g., rb'abc', rB'abc', Rb'abc', RB'abc').
func hasRawBytesRbPrefix(text string) bool {
	for i := 0; i+2 < len(text); i++ {
		if i > 0 && isWordChar(text[i-1]) {
			continue
		}
		c0 := text[i]
		c1 := text[i+1]
		c2 := text[i+2]
		if (c0 == 'r' || c0 == 'R') && (c1 == 'b' || c1 == 'B') && (c2 == '\'' || c2 == '"') {
			return true
		}
	}
	return false
}

// ANTLR grammar only supports lowercase '0x' prefix for hexadecimal integer literals,
// whereas Pratt parser supports both '0x' and '0X' (e.g., '0X12', '0X12u').
func hasUppercaseHexPrefix(text string) bool {
	for i := 0; i+1 < len(text); i++ {
		if i > 0 && isWordChar(text[i-1]) {
			continue
		}
		if text[i] == '0' && text[i+1] == 'X' {
			return true
		}
	}
	return false
}

func getAllNodes(a *ast.AST) []ast.NavigableExpr {
	var nodes []ast.NavigableExpr
	if a == nil || a.Expr() == nil {
		return nodes
	}
	nodes = append(nodes, ast.MatchDescendants(ast.NavigateAST(a), ast.AllMatcher())...)
	for _, macroCall := range a.SourceInfo().MacroCalls() {
		macroAST := ast.NewAST(macroCall, a.SourceInfo())
		nodes = append(nodes, ast.MatchDescendants(ast.NavigateAST(macroAST), ast.AllMatcher())...)
	}
	return nodes
}

// ANTLR grammar allows a standalone comma in empty lists, maps, and structs
// (e.g., '[,]', '{,}', 'Msg{,}'), whereas Pratt parser requires at least one element/entry
// before a trailing comma.
func hasEmptyCollectionWithComma(antlrAST *ast.AST, text string) bool {
	if antlrAST == nil {
		return false
	}
	sourceInfo := antlrAST.SourceInfo()
	for _, node := range getAllNodes(antlrAST) {
		expr := node
		isEmptyCollection := false
		closeChar := byte('}')
		switch expr.Kind() {
		case ast.ListKind:
			if expr.AsList().Size() == 0 {
				isEmptyCollection = true
				closeChar = ']'
			}
		case ast.MapKind:
			if expr.AsMap().Size() == 0 {
				isEmptyCollection = true
			}
		case ast.StructKind:
			if len(expr.AsStruct().Fields()) == 0 {
				isEmptyCollection = true
			}
		}
		if !isEmptyCollection {
			continue
		}
		offsetRange, found := sourceInfo.GetOffsetRange(expr.ID())
		if !found || offsetRange.Start < 0 || int(offsetRange.Start) >= len(text) {
			continue
		}
		openPos := int(offsetRange.Start)
		closePos := strings.IndexByte(text[openPos+1:], closeChar)
		if closePos != -1 {
			if strings.Contains(text[openPos+1:openPos+1+closePos], ",") {
				return true
			}
		}
	}
	return false
}

// hasOnlyRecursionLimitErrors returns true if all parse errors are recursion limit exceeded errors.
func hasOnlyRecursionLimitErrors(errs *common.Errors) bool {
	if errs == nil || len(errs.GetErrors()) == 0 {
		return false
	}
	for _, e := range errs.GetErrors() {
		if !strings.Contains(e.Message, "recursion limit exceeded") &&
			!strings.Contains(e.Message, "max recursion depth exceeded") {
			return false
		}
	}
	return true
}

// normalizeLeadingDotIdentPositions: Pratt parser records the start of a leading-dot identifier
// (e.g., '.R') at the '.' token, whereas ANTLR records it at the identifier token following '.'.
func normalizeLeadingDotIdentPositions(prattProto, antlrProto *exprpb.ParsedExpr) {
	if prattProto == nil || antlrProto == nil ||
		prattProto.SourceInfo == nil || antlrProto.SourceInfo == nil {
		return
	}
	antlrPositions := antlrProto.SourceInfo.Positions
	prattPositions := prattProto.SourceInfo.Positions
	if antlrPositions == nil || prattPositions == nil {
		return
	}

	var visitExpr func(e *exprpb.Expr)
	visitExpr = func(e *exprpb.Expr) {
		if e == nil {
			return
		}
		if ident := e.GetIdentExpr(); ident != nil {
			if strings.HasPrefix(ident.GetName(), ".") {
				if pos, found := antlrPositions[e.GetId()]; found {
					prattPositions[e.GetId()] = pos
				}
			}
		}
		switch k := e.GetExprKind().(type) {
		case *exprpb.Expr_CallExpr:
			if k.CallExpr.GetTarget() != nil {
				visitExpr(k.CallExpr.GetTarget())
			}
			for _, arg := range k.CallExpr.GetArgs() {
				visitExpr(arg)
			}
		case *exprpb.Expr_ComprehensionExpr:
			visitExpr(k.ComprehensionExpr.GetIterRange())
			visitExpr(k.ComprehensionExpr.GetAccuInit())
			visitExpr(k.ComprehensionExpr.GetLoopCondition())
			visitExpr(k.ComprehensionExpr.GetLoopStep())
			visitExpr(k.ComprehensionExpr.GetResult())
		case *exprpb.Expr_ListExpr:
			for _, elem := range k.ListExpr.GetElements() {
				visitExpr(elem)
			}
		case *exprpb.Expr_SelectExpr:
			visitExpr(k.SelectExpr.GetOperand())
		case *exprpb.Expr_StructExpr:
			for _, entry := range k.StructExpr.GetEntries() {
				if entry.GetMapKey() != nil {
					visitExpr(entry.GetMapKey())
				}
				if entry.GetValue() != nil {
					visitExpr(entry.GetValue())
				}
			}
		}
	}

	visitExpr(prattProto.GetExpr())
	for _, call := range prattProto.GetSourceInfo().GetMacroCalls() {
		visitExpr(call)
	}
}

func astToParsedExpr(a *ast.AST) (*exprpb.ParsedExpr, error) {
	e, err := ast.ExprToProto(a.Expr())
	if err != nil {
		return nil, err
	}
	info, err := ast.SourceInfoToProto(a.SourceInfo())
	if err != nil {
		return nil, err
	}
	return &exprpb.ParsedExpr{
		Expr:       e,
		SourceInfo: info,
	}, nil
}

// FuzzPrattParser fuzzes the CEL parser by comparing ANTLR and Pratt parser outputs.
func FuzzPrattParser(data []byte) int {
	text := string(data)
	if hasRawBytesRbPrefix(text) || hasUppercaseHexPrefix(text) {
		return 0
	}

	source := common.NewTextSource(text)
	antlrAST, antlrErrs := antlrParser.Parse(source)
	prattAST, prattErrs := prattParser.Parse(source)

	antlrHasErr := len(antlrErrs.GetErrors()) > 0
	prattHasErr := len(prattErrs.GetErrors()) > 0

	if antlrHasErr != prattHasErr {
		if !antlrHasErr && prattHasErr && hasEmptyCollectionWithComma(antlrAST, text) {
			return 0
		}
		// For some expressions the two parsers allow different recursion depths;
		// specifically, parens nested inside an operand are charged against the
		// depth reached so far rather than accumulating on top of the enclosing parens,
		// so the Pratt parser accepts inputs that ANTLR rejects.
		if antlrHasErr && !prattHasErr && hasOnlyRecursionLimitErrors(antlrErrs) {
			return 0
		}
		panic(fmt.Sprintf("Parser error mismatch for input %q:\nANTLR hasError=%t (%s)\nPratt hasError=%t (%s)",
			text, antlrHasErr, antlrErrs.ToDisplayString(), prattHasErr, prattErrs.ToDisplayString()))
	}

	if !antlrHasErr {
		antlrProto, err := astToParsedExpr(antlrAST)
		if err != nil {
			panic(fmt.Sprintf("failed to convert ANTLR AST to proto: %v", err))
		}
		prattProto, err := astToParsedExpr(prattAST)
		if err != nil {
			panic(fmt.Sprintf("failed to convert Pratt AST to proto: %v", err))
		}

		if !proto.Equal(antlrProto, prattProto) {
			normalizeLeadingDotIdentPositions(prattProto, antlrProto)
			if !proto.Equal(antlrProto, prattProto) {
				panic(fmt.Sprintf("AST mismatch for input %q:\nANTLR Proto: %v\nPratt Proto: %v",
					text, antlrProto, prattProto))
			}
		}
	}

	return 1
}
