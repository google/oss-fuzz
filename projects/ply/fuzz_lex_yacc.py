#!/usr/bin/python3
# Copyright 2022 Google LLC
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
"""Fuzzer that creates a simple grammar and parsing routines,
and then uses that to parse the fuzzer data. The grammer and
parsing routines can be extended based on coverage analysis."""

import sys
import atheris
import ply.lex as lex
import ply.yacc as yacc


# A simple lexer
tokens = [
    "PLUS",
    "MINUS",
    "TIMES",
    "NUMBER",
    ]

t_PLUS = r'\+'
t_MINUS = r'-'
t_TIMES = "\*"
t_ignore = ' \t'

def t_NUMBER(t):
    r'\d+'
    t.value = int(t.value)
    return t

def t_ignore_newline(t):
    r'\n+'
    t.lexer.lineno += t.value.count('\n')

def t_error(t):
    pass


# Some simple parser rules. Note that grammar rules are written as docstrings
# in each function.
def p_expression(p):
    '''
    expression : term PLUS term
               | term MINUS term
    '''
    p[0] = ('binop', p[2], p[1], p[3])


def p_expression_term(p):
    '''
    expression : term
    '''
    p[0] = p[1]

def p_term(p):
    '''
    term : factor TIMES factor
    '''
    p[0] = ('binop', p[2], p[1], p[3])

def p_term_factor(p):
    '''
    term : factor
    '''
    p[0] = p[1]

def p_factor_number(p):
    '''
    factor : NUMBER
    '''
    p[0] = ('number', p[1])

def p_error(p):
    pass
# end of parser functions

def TestOneInput(data):
    fdp = atheris.FuzzedDataProvider(data)
    lex.lex()
    parser = yacc.yacc()
    try:
        parser.parse(fdp.ConsumeUnicodeNoSurrogates(sys.maxsize))
    except lex.LexError:
        pass

def main():
    atheris.instrument_all()
    atheris.Setup(sys.argv, TestOneInput, enable_python_coverage=True)
    atheris.Fuzz()

if __name__ == "__main__":
    main()
