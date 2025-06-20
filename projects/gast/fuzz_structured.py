#!/usr/bin/python3
# Copyright 2025 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
import sys
import math
import atheris
import string
import ast, gast


def gen_identifier(fdp):
    return "".join(
        string.ascii_lowercase[
            fdp.ConsumeIntInRange(0, len(string.ascii_lowercase) - 1)
        ]
        for i in range(fdp.ConsumeIntInRange(1, 8))
    )


def gen_mod(fdp):
    ops = [gen_Module]
    op_idx = fdp.ConsumeIntInRange(0, len(ops) - 1)
    return ops[op_idx](fdp)


def gen_Module(fdp):
    stmt_count = fdp.ConsumeIntInRange(1, 8)
    type_ignore_count = fdp.ConsumeIntInRange(0, 2)
    return ast.Module(
        [gen_stmt(fdp) for _ in range(stmt_count)],
        [gen_type_ignore(fdp) for _ in range(type_ignore_count)],
    )


def gen_type_ignore(fdp):
    return ast.TypeIgnore(fdp.ConsumeIntInRange(0, 4), "")


# stmt


def gen_stmt(fdp):
    stmts = [
        gen_Expr,
        gen_FunctionDef,
        gen_AsyncFunctionDef,
        gen_ClassDef,
        gen_Return,
        gen_Delete,
        gen_Assign,
        gen_AugAssign,
        gen_AnnAssign,
        gen_For,
        gen_AsyncFor,
        gen_While,
        gen_If,
        gen_With,
        gen_AsyncWith,
        gen_Match,
        gen_Raise,
        gen_Try,
        gen_Assert,
        gen_Import,
        gen_ImportFrom,
        gen_Global,
        gen_Nonlocal,
        gen_Expr,
        gen_Pass,
        gen_Break,
        gen_Continue,
    ]
    stmt_idx = fdp.ConsumeIntInRange(0, len(stmts) - 1)
    return stmts[stmt_idx](fdp)


def gen_FunctionDef(fdp):
    return ast.FunctionDef(
        gen_identifier(fdp),
        gen_arguments(fdp),
        [gen_stmt(fdp) for _ in range(fdp.ConsumeIntInRange(1, 4))],
        [gen_expr(fdp) for _ in range(fdp.ConsumeIntInRange(0, 3))],
        gen_expr(fdp) if fdp.ConsumeBool() else None,
        fdp.ConsumeUnicode(4) if fdp.ConsumeBool() else None,
    )


def gen_AsyncFunctionDef(fdp):
    return ast.AsyncFunctionDef(
        gen_identifier(fdp),
        gen_arguments(fdp),
        [gen_stmt(fdp) for _ in range(fdp.ConsumeIntInRange(1, 4))],
        [gen_expr(fdp) for _ in range(fdp.ConsumeIntInRange(0, 3))],
        gen_expr(fdp) if fdp.ConsumeBool() else None,
        fdp.ConsumeUnicode(4) if fdp.ConsumeBool() else None,
    )


def gen_keyword(fdp):
    return ast.keyword(
        gen_identifier(fdp) if fdp.ConsumeBool() else None, gen_expr(fdp)
    )


def gen_ClassDef(fdp):
    return ast.ClassDef(
        gen_identifier(fdp),
        [gen_expr(fdp) for _ in range(fdp.ConsumeIntInRange(0, 2))],
        [gen_keyword(fdp) for _ in range(fdp.ConsumeIntInRange(0, 2))],
        [gen_stmt(fdp) for _ in range(fdp.ConsumeIntInRange(1, 4))],
        [gen_expr(fdp) for _ in range(fdp.ConsumeIntInRange(0, 2))],
    )


def gen_Return(fdp):
    return ast.Return(gen_expr(fdp) if fdp.ConsumeBool() else None)


def gen_Delete(fdp):
    return ast.Delete([gen_expr(fdp) for _ in range(fdp.ConsumeIntInRange(1, 4))])


def gen_Assign(fdp):
    return ast.Assign(
        [gen_expr(fdp) for _ in range(fdp.ConsumeIntInRange(1, 4))],
        gen_expr(fdp),
        fdp.ConsumeUnicode(4) if fdp.ConsumeBool() else None,
    )


def gen_AugAssign(fdp):
    return ast.AugAssign(
        gen_expr(fdp),
        gen_operator(fdp),
        gen_expr(fdp),
    )


def gen_AnnAssign(fdp):
    return ast.AnnAssign(
        gen_expr(fdp),
        gen_expr(fdp),
        gen_expr(fdp) if fdp.ConsumeBool() else None,
        fdp.ConsumeIntInRange(0, 4),
    )


def gen_For(fdp):
    return ast.For(
        gen_expr(fdp),
        gen_expr(fdp),
        [gen_stmt(fdp) for _ in range(fdp.ConsumeIntInRange(1, 4))],
        [gen_stmt(fdp) for _ in range(fdp.ConsumeIntInRange(0, 4))],
        fdp.ConsumeUnicode(4) if fdp.ConsumeBool() else None,
    )


def gen_AsyncFor(fdp):
    return ast.AsyncFor(
        gen_expr(fdp),
        gen_expr(fdp),
        [gen_stmt(fdp) for _ in range(fdp.ConsumeIntInRange(1, 4))],
        [gen_stmt(fdp) for _ in range(fdp.ConsumeIntInRange(0, 4))],
        fdp.ConsumeUnicode(4) if fdp.ConsumeBool() else None,
    )


def gen_arguments(fdp):
    posonly_argcount = fdp.ConsumeIntInRange(0, 3)
    argcount = fdp.ConsumeIntInRange(0, 3)
    kwonlyargcount = fdp.ConsumeIntInRange(0, 3)
    return ast.arguments(
        [gen_arg(fdp) for _ in range(posonly_argcount)],
        [gen_arg(fdp) for _ in range(argcount)],
        gen_arg(fdp) if fdp.ConsumeBool() else None,
        [gen_arg(fdp) for _ in range(kwonlyargcount)],
        [
            gen_expr(fdp)
            for _ in range(fdp.ConsumeIntInRange(0, posonly_argcount + argcount))
        ],
        gen_arg(fdp) if fdp.ConsumeBool() else None,
        [gen_expr(fdp) for _ in range(fdp.ConsumeIntInRange(0, kwonlyargcount))],
    )


def gen_While(fdp):
    return ast.While(
        gen_expr(fdp),
        [gen_stmt(fdp) for _ in range(fdp.ConsumeIntInRange(1, 4))],
        [gen_stmt(fdp) for _ in range(fdp.ConsumeIntInRange(0, 4))],
    )


def gen_If(fdp):
    return ast.If(
        gen_expr(fdp),
        [gen_stmt(fdp) for _ in range(fdp.ConsumeIntInRange(1, 4))],
        [gen_stmt(fdp) for _ in range(fdp.ConsumeIntInRange(0, 4))],
    )


def gen_With(fdp):
    return ast.With(
        [gen_withitem(fdp) for _ in range(fdp.ConsumeIntInRange(1, 4))],
        [gen_stmt(fdp) for _ in range(fdp.ConsumeIntInRange(1, 4))],
        gen_identifier(fdp),
    )


def gen_AsyncWith(fdp):
    return ast.AsyncWith(
        [gen_withitem(fdp) for _ in range(fdp.ConsumeIntInRange(1, 4))],
        [gen_stmt(fdp) for _ in range(fdp.ConsumeIntInRange(1, 4))],
        gen_identifier(fdp),
    )


def gen_withitem(fdp):
    return ast.withitem(gen_expr(fdp), gen_expr(fdp) if fdp.ConsumeBool() else None)


def gen_Match(fdp):
    return ast.Match(
        gen_expr(fdp),
        [gen_match_case(fdp) for _ in range(fdp.ConsumeIntInRange(1, 4))],
    )


def gen_match_case(fdp):
    return ast.match_case(
        gen_pattern(fdp),
        gen_expr(fdp) if fdp.ConsumeBool() else None,
        [gen_stmt(fdp) for _ in range(fdp.ConsumeIntInRange(1, 4))],
    )


def gen_constant(fdp):
    return fdp.ConsumeIntInRange(1, 4)


def gen_pattern(fdp):
    case = fdp.ConsumeIntInRange(1, 8)
    if case == 1:
        return ast.MatchValue(gen_expr(fdp))
    elif case == 2:
        return ast.MatchSingleton(gen_constant(fdp))
    elif case == 3:
        return ast.MatchSequence(
            [gen_pattern(fdp) for _ in range(fdp.ConsumeIntInRange(1, 4))]
        )
    elif case == 4:
        nelts = fdp.ConsumeIntInRange(1, 4)
        return ast.MatchMapping(
            [gen_expr(fdp) for _ in range(nelts)],
            [gen_pattern(fdp) for _ in range(nelts)],
            gen_identifier(fdp) if fdp.ConsumeBool() else None,
        )
    elif case == 5:
        nkwd = fdp.ConsumeIntInRange(0, 2)
        return ast.MatchClass(
            gen_expr(fdp),
            [gen_pattern(fdp) for _ in range(fdp.ConsumeIntInRange(0, 2))],
            [gen_identifier(fdp) for _ in range(nkwd)],
            [gen_pattern(fdp) for _ in range(nkwd)],
        )
    elif case == 6:
        return ast.MatchStar(gen_identifier(fdp) if fdp.ConsumeBool() else None)
    elif case == 7:
        return ast.MatchAs(
            gen_pattern(fdp) if fdp.ConsumeBool() else None,
            gen_identifier(fdp) if fdp.ConsumeBool() else None,
        )
    elif case == 8:
        return ast.MatchOr(
            [gen_pattern(fdp) for _ in range(fdp.ConsumeIntInRange(2, 3))]
        )


def gen_Raise(fdp):
    return ast.Raise(
        gen_expr(fdp) if fdp.ConsumeBool() else None,
        gen_expr(fdp) if fdp.ConsumeBool() else None,
    )


def gen_Try(fdp):
    return ast.Try(
        [gen_stmt(fdp) for _ in range(fdp.ConsumeIntInRange(1, 4))],
        [gen_excepthandler(fdp) for _ in range(fdp.ConsumeIntInRange(1, 4))],
        [gen_stmt(fdp) for _ in range(fdp.ConsumeIntInRange(0, 2))],
        [gen_stmt(fdp) for _ in range(fdp.ConsumeIntInRange(0, 2))],
    )


def gen_excepthandler(fdp):
    return ast.ExceptHandler(
        gen_expr(fdp) if fdp.ConsumeBool() else None,
        gen_identifier(fdp) if fdp.ConsumeBool() else None,
        [gen_stmt(fdp) for _ in range(fdp.ConsumeIntInRange(1, 4))],
    )


def gen_Assert(fdp):
    return ast.Assert(gen_expr(fdp), gen_expr(fdp) if fdp.ConsumeBool() else None)


def gen_Import(fdp):
    return ast.Import([gen_alias(fdp) for _ in range(fdp.ConsumeIntInRange(1, 4))])


def gen_alias(fdp):
    return ast.alias(
        gen_identifier(fdp), gen_identifier(fdp) if fdp.ConsumeBool() else None
    )


def gen_ImportFrom(fdp):
    return ast.ImportFrom(
        gen_identifier(fdp) if fdp.ConsumeBool() else None,
        [gen_alias(fdp) for _ in range(fdp.ConsumeIntInRange(1, 4))],
        fdp.ConsumeIntInRange(0, 3) if fdp.ConsumeBool() else None,
    )


def gen_Global(fdp):
    return ast.Global([gen_identifier(fdp) for _ in range(fdp.ConsumeIntInRange(1, 4))])


def gen_Nonlocal(fdp):
    return ast.Nonlocal(
        [gen_identifier(fdp) for _ in range(fdp.ConsumeIntInRange(1, 4))]
    )


def gen_Expr(fdp):
    return ast.Expr(gen_expr(fdp))


def gen_Pass(fdp):
    return ast.Pass()


def gen_Break(fdp):
    return ast.Break()


def gen_Continue(fdp):
    return ast.Continue()


## expr


def gen_operator(fdp):
    ops = [
        ast.Add,
        ast.Sub,
        ast.Mult,
        ast.MatMult,
        ast.Div,
        ast.Mod,
        ast.Pow,
        ast.LShift,
        ast.RShift,
        ast.BitOr,
        ast.BitXor,
        ast.BitAnd,
        ast.FloorDiv,
    ]
    ops_idx = fdp.ConsumeIntInRange(0, len(ops) - 1)
    return ops[ops_idx]()


def gen_arg(fdp):
    return ast.arg(
        gen_identifier(fdp),
        gen_expr(fdp) if fdp.ConsumeBool() else None,
        fdp.ConsumeUnicode(4) if fdp.ConsumeBool() else None,
    )


def gen_BoolOp(fdp):
    values_len = fdp.ConsumeIntInRange(2, 3)
    return ast.BoolOp(gen_boolop(fdp), [gen_expr(fdp) for _ in range(values_len)])


def gen_NamedExpr(fdp):
    return ast.NamedExpr(gen_expr(fdp), gen_expr(fdp))


def gen_BinOp(fdp):
    return ast.BinOp(gen_expr(fdp), gen_operator(fdp), gen_expr(fdp))


def gen_UnaryOp(fdp):
    return ast.UnaryOp(gen_unaryop(fdp), gen_expr(fdp))


def gen_unaryop(fdp):
    ops = [ast.Invert, ast.Not, ast.UAdd, ast.USub]
    ops_idx = fdp.ConsumeIntInRange(0, len(ops) - 1)
    return ops[ops_idx]()


def gen_Lambda(fdp):
    return ast.Lambda(gen_arguments(fdp), gen_expr(fdp))


def gen_IfExp(fdp):
    return ast.IfExp(gen_expr(fdp), gen_expr(fdp), gen_expr(fdp))


def gen_Dict(fdp):
    nelts = fdp.ConsumeIntInRange(0, 4)
    return ast.Dict(
        [gen_expr(fdp) for _ in range(nelts)], [gen_expr(fdp) for _ in range(nelts)]
    )


def gen_Set(fdp):
    return ast.Set([gen_expr(fdp) for _ in range(fdp.ConsumeIntInRange(1, 4))])


def gen_boolop(fdp):
    op_len = fdp.ConsumeIntInRange(0, 1)
    return [ast.And(), ast.Or()][op_len]


def gen_comprehension(fdp):
    return ast.comprehension(
        gen_expr(fdp),
        gen_expr(fdp),
        [gen_expr(fdp) for _ in range(fdp.ConsumeIntInRange(0, 2))],
        fdp.ConsumeIntInRange(0, 4),
    )


def gen_ListComp(fdp):
    return ast.ListComp(
        gen_expr(fdp),
        [gen_comprehension(fdp) for _ in range(fdp.ConsumeIntInRange(1, 4))],
    )


def gen_SetComp(fdp):
    return ast.SetComp(
        gen_expr(fdp),
        [gen_comprehension(fdp) for _ in range(fdp.ConsumeIntInRange(1, 4))],
    )


def gen_DictComp(fdp):
    return ast.DictComp(
        gen_expr(fdp),
        gen_expr(fdp),
        [gen_comprehension(fdp) for _ in range(fdp.ConsumeIntInRange(1, 4))],
    )


def gen_GeneratorExp(fdp):
    return ast.GeneratorExp(
        gen_expr(fdp),
        [gen_comprehension(fdp) for _ in range(fdp.ConsumeIntInRange(1, 4))],
    )


def gen_Await(fdp):
    return ast.Await(gen_expr(fdp))


def gen_Yield(fdp):
    return ast.Yield(gen_expr(fdp) if fdp.ConsumeBool() else None)


def gen_YieldFrom(fdp):
    return ast.YieldFrom(gen_expr(fdp))


def gen_Compare(fdp):
    nops = fdp.ConsumeIntInRange(0, 1)
    return ast.Compare(
        gen_expr(fdp),
        [gen_cmpop(fdp) for _ in range(nops)],
        [gen_expr(fdp) for _ in range(nops)],
    )


def gen_cmpop(fdp):
    ops = [
        ast.Eq,
        ast.NotEq,
        ast.Lt,
        ast.LtE,
        ast.Gt,
        ast.GtE,
        ast.Is,
        ast.IsNot,
        ast.In,
        ast.NotIn,
    ]
    ops_idx = fdp.ConsumeIntInRange(0, len(ops) - 1)
    return ops[ops_idx]()


def gen_Call(fdp):
    return ast.Call(
        gen_expr_context(fdp),
        [gen_expr(fdp) for _ in range(fdp.ConsumeIntInRange(0, 4))],
        [gen_keyword(fdp) for _ in range(fdp.ConsumeIntInRange(0, 2))],
    )


def gen_FormattedValue(fdp):
    return ast.FormattedValue(
        gen_expr(fdp),
        fdp.ConsumeIntInRange(0, 4),
        gen_expr(fdp) if fdp.ConsumeBool() else None,
    )


def gen_JoinedStr(fdp):
    return ast.JoinedStr([gen_fstring(fdp) for _ in range(fdp.ConsumeIntInRange(1, 4))])


def gen_fstring(fdp):
    ops = [gen_JoinedStr, gen_StrConstant, gen_FormattedValue]
    op_len = fdp.ConsumeIntInRange(0, len(ops) - 1)
    return ops[op_len](fdp)


def gen_StrConstant(fdp):
    return ast.Constant(fdp.ConsumeUnicode(4), None)


def gen_IntConstant(fdp):
    return ast.Constant(fdp.ConsumeInt(4), None)


def gen_Constant(fdp):
    ops = [gen_StrConstant, gen_IntConstant]
    op_len = fdp.ConsumeIntInRange(0, len(ops) - 1)
    return ops[op_len](fdp)


def gen_Attribute(fdp):
    return ast.Attribute(gen_expr(fdp), gen_identifier(fdp), gen_expr_context(fdp))


def gen_Subscript(fdp):
    return ast.Subscript(gen_expr(fdp), gen_expr(fdp), gen_expr_context(fdp))


def gen_Starred(fdp):
    return ast.Starred(gen_expr(fdp), gen_expr_context(fdp))


def gen_Name(fdp):
    return ast.Name(gen_identifier(fdp), gen_expr_context(fdp))


def gen_List(fdp):
    return ast.List([], gen_expr_context(fdp))


def gen_Tuple(fdp):
    return ast.Tuple([], gen_expr_context(fdp))


def gen_Slice(fdp):
    return ast.Slice(
        gen_expr(fdp) if fdp.ConsumeBool() else None,
        gen_expr(fdp) if fdp.ConsumeBool() else None,
        gen_expr(fdp) if fdp.ConsumeBool() else None,
    )


def gen_expr(fdp):
    ops = [
        gen_BoolOp,
        gen_NamedExpr,
        gen_BinOp,
        gen_UnaryOp,
        gen_Lambda,
        gen_IfExp,
        gen_Dict,
        gen_Set,
        gen_ListComp,
        gen_SetComp,
        gen_DictComp,
        gen_GeneratorExp,
        gen_Await,
        gen_Yield,
        gen_YieldFrom,
        gen_Compare,
        gen_Call,
        gen_FormattedValue,
        gen_JoinedStr,
        gen_Constant,
        gen_Attribute,
        gen_Subscript,
        gen_Starred,
        gen_Name,
        gen_List,
        gen_Tuple,
        gen_Slice,
    ]
    op_len = fdp.ConsumeIntInRange(0, len(ops) - 1)
    return ops[op_len](fdp)


def gen_expr_context(fdp):
    expr_contexts = [ast.Load, ast.Store, ast.Del, ast.AugLoad, ast.AugStore, ast.Param]
    expr_context_idx = fdp.ConsumeIntInRange(0, len(expr_contexts) - 1)
    return expr_contexts[expr_context_idx]()


# expr


def TestOneInput(data):
    fdp = atheris.FuzzedDataProvider(data)
    try:
        tree = ast.fix_missing_locations(gen_mod(fdp))
    except RecursionError:
        return

    try:
        code = ast.unparse(tree)
        tree = ast.parse(code)
    except (SyntaxError, ValueError, RecursionError) as e:
        return

    # Any valid tree should be processable
    try:
        gtree = gast.ast_to_gast(tree)
        gast.dump(gtree)
        converted_ast = gast.gast_to_ast(gtree)
        code = gast.unparse(gtree)
    except RecursionError:
        return


def main():
    atheris.instrument_all()
    atheris.Setup(sys.argv, TestOneInput, enable_python_coverage=True)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
