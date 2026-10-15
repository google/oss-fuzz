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
//
////////////////////////////////////////////////////////////////////////////////

#![no_main]

use cel::common::ast::{EntryExpr, Expr, IdedExpr, SourceInfo};
use cel::parser::{ParseErrors, Parser, PrattParser};
use libfuzzer_sys::fuzz_target;

fn is_word_char(c: u8) -> bool {
    c.is_ascii_alphanumeric() || c == b'_'
}

// ANTLR grammar only supports 'br' prefix order for raw byte literals (e.g., br'abc'),
// whereas Pratt parser supports both 'br' and 'rb' (e.g., rb'abc', rB'abc', Rb'abc', RB'abc').
fn has_raw_bytes_rb_prefix(text: &str) -> bool {
    let bytes = text.as_bytes();
    if bytes.len() < 3 {
        return false;
    }
    for i in 0..bytes.len() - 2 {
        if i > 0 && is_word_char(bytes[i - 1]) {
            continue;
        }
        let c0 = bytes[i];
        let c1 = bytes[i + 1];
        let c2 = bytes[i + 2];
        if (c0 == b'r' || c0 == b'R')
            && (c1 == b'b' || c1 == b'B')
            && (c2 == b'\'' || c2 == b'"')
        {
            return true;
        }
    }
    false
}

// ANTLR grammar only supports lowercase '0x' prefix for hexadecimal integer literals,
// whereas Pratt parser supports both '0x' and '0X' (e.g., '0X12', '0X12u').
fn has_uppercase_hex_prefix(text: &str) -> bool {
    let bytes = text.as_bytes();
    if bytes.len() < 2 {
        return false;
    }
    for i in 0..bytes.len() - 1 {
        if i > 0 && is_word_char(bytes[i - 1]) {
            continue;
        }
        if bytes[i] == b'0' && bytes[i + 1] == b'X' {
            return true;
        }
    }
    false
}

// ANTLR parser incorrectly rejects raw multiline string/bytes literals containing '\0'.
fn has_raw_multiline_string_with_null(text: &str) -> bool {
    ["\"\"\"", "'''"].into_iter().any(|delim| {
        text.match_indices(delim).any(|(i, _)| {
            let before = text[..i].strip_suffix(['b', 'B']).unwrap_or(&text[..i]);
            let rest = &text[i + delim.len()..];
            before.ends_with(['r', 'R'])
                && rest
                    .find(delim)
                    .is_some_and(|end| rest[..end].contains('\0'))
        })
    })
}

fn collect_all_nodes<'a>(expr: &'a IdedExpr, out: &mut Vec<&'a IdedExpr>) {
    out.push(expr);
    match &expr.expr {
        Expr::Unspecified | Expr::Ident(_) | Expr::Literal(_) => {}
        Expr::Call(call) => {
            if let Some(target) = &call.target {
                collect_all_nodes(target, out);
            }
            for arg in &call.args {
                collect_all_nodes(arg, out);
            }
        }
        Expr::Comprehension(comp) => {
            collect_all_nodes(&comp.iter_range, out);
            collect_all_nodes(&comp.accu_init, out);
            collect_all_nodes(&comp.loop_cond, out);
            collect_all_nodes(&comp.loop_step, out);
            collect_all_nodes(&comp.result, out);
        }
        Expr::List(list) => {
            for elem in &list.elements {
                collect_all_nodes(elem, out);
            }
        }
        Expr::Map(map) => {
            for entry in &map.entries {
                if let EntryExpr::MapEntry(me) = &entry.expr {
                    collect_all_nodes(&me.key, out);
                    collect_all_nodes(&me.value, out);
                }
            }
        }
        Expr::Select(sel) => {
            collect_all_nodes(&sel.operand, out);
        }
        Expr::Struct(s) => {
            for entry in &s.entries {
                if let EntryExpr::StructField(sf) = &entry.expr {
                    collect_all_nodes(&sf.value, out);
                }
            }
        }
    }
}

fn has_comma_before_close(chars: impl Iterator<Item = char>, close_char: char) -> bool {
    let mut has_comma = false;
    for c in chars {
        if c == close_char {
            return has_comma;
        }
        if c == ',' {
            has_comma = true;
        }
    }
    false
}

// ANTLR grammar allows a standalone comma in empty lists, maps, and structs
// (e.g., '[,]', '{,}', 'Msg{,}'), whereas Pratt parser requires at least one element/entry
// before a trailing comma.
fn has_empty_collection_with_comma(
    antlr_ast: &IdedExpr,
    source_info: &SourceInfo,
    text: &str,
) -> bool {
    let mut nodes = Vec::new();
    collect_all_nodes(antlr_ast, &mut nodes);

    for node in nodes {
        let (open_char, close_char) = match &node.expr {
            Expr::List(list) if list.elements.is_empty() => ('[', ']'),
            Expr::Map(map) if map.entries.is_empty() => ('{', '}'),
            Expr::Struct(s) if s.entries.is_empty() => ('{', '}'),
            _ => continue,
        };

        let Some((start, _)) = source_info.offset_for(node.id) else {
            continue;
        };
        let open_pos = start as usize;

        if open_pos < text.len() && text.is_char_boundary(open_pos) {
            let mut chars = text[open_pos..].chars();
            if chars.next() == Some(open_char) && has_comma_before_close(chars, close_char) {
                return true;
            }
        }
    }
    false
}

// Returns true if all parse errors are recursion limit exceeded errors.
fn has_only_recursion_limit_errors(errs: &ParseErrors) -> bool {
    if errs.errors.is_empty() {
        return false;
    }
    errs.errors.iter().all(|e| {
        let msg_lower = e.msg.to_ascii_lowercase();
        if msg_lower.contains("recursion limit") || msg_lower.contains("recursion depth") {
            return true;
        }
        if let Some(src) = &e.source {
            let src_lower = src.to_string().to_ascii_lowercase();
            if src_lower.contains("recursion limit") || src_lower.contains("recursion depth") {
                return true;
            }
        }
        false
    })
}

fuzz_target!(|text: &str| {
    if has_raw_bytes_rb_prefix(text)
        || has_uppercase_hex_prefix(text)
        || has_raw_multiline_string_with_null(text)
    {
        return;
    }

    let antlr_res = Parser::new()
        .enable_optional_syntax(true)
        .enable_ident_escape_syntax(true)
        .max_recursion_depth(32)
        .error_recovery_limit(4)
        .parse_with_source_info(text);

    let pratt_res = PrattParser::new()
        .enable_optional_syntax(true)
        .enable_ident_escape_syntax(true)
        .max_recursion_depth(32)
        .error_recovery_limit(4)
        .parse(text);

    match (antlr_res, pratt_res) {
        (Ok((antlr_ast, source_info)), Err(pratt_errs)) => {
            if has_empty_collection_with_comma(&antlr_ast, &source_info, text) {
                return;
            }
            panic!(
                "Parser error mismatch for input {:?}:\nANTLR hasError=false\nPratt hasError=true ({})",
                text, pratt_errs
            );
        }
        (Err(antlr_errs), Ok(_)) => {
            // For some expressions the two parsers allow different recursion depths;
            // specifically, parens nested inside an operand are charged against the
            // depth reached so far rather than accumulating on top of the enclosing parens,
            // so the Pratt parser accepts inputs that ANTLR rejects.
            if has_only_recursion_limit_errors(&antlr_errs) {
                return;
            }
            panic!(
                "Parser error mismatch for input {:?}:\nANTLR hasError=true ({})\nPratt hasError=false",
                text, antlr_errs
            );
        }
        (Err(_), Err(_)) => {}
        (Ok((antlr_ast, _)), Ok(pratt_ast)) => {
            if antlr_ast != pratt_ast {
                panic!(
                    "AST mismatch for input {:?}:\nANTLR AST: {:#?}\nPratt AST: {:#?}",
                    text, antlr_ast, pratt_ast
                );
            }
        }
    }
});
