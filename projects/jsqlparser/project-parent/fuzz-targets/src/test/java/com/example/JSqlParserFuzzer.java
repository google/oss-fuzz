// Copyright 2023 Google LLC
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

package com.example;

import com.code_intelligence.jazzer.api.FuzzedDataProvider;
import com.code_intelligence.jazzer.junit.FuzzTest;

import net.sf.jsqlparser.JSQLParserException;
import net.sf.jsqlparser.parser.CCJSqlParserUtil;
import net.sf.jsqlparser.parser.TokenMgrException;

class JSqlParserFuzzer {
    @FuzzTest
    void myFuzzTest(FuzzedDataProvider data) {
        String simpleSql = data.consumeString(1000);
        String sqlScript = data.consumeString(1000);
        String expression = data.consumeString(1000);
        String ast = data.consumeString(1000);
        String condExp = data.consumeString(1000);

        try {
            CCJSqlParserUtil.parse(
                    simpleSql,
                    parser -> parser
                            .withSquareBracketQuotation(data.consumeBoolean())
                            .withAllowComplexParsing(data.consumeBoolean())
                            .withUnsupportedStatements(data.consumeBoolean())
                            .withBackslashEscapeCharacter(data.consumeBoolean())
            );
        } catch (JSQLParserException e) {
        }

        try {
            CCJSqlParserUtil.parseStatements(
                    sqlScript,
                    parser -> parser
                            .withSquareBracketQuotation(data.consumeBoolean())
                            .withAllowComplexParsing(data.consumeBoolean())
                            .withUnsupportedStatements(data.consumeBoolean())
                            .withBackslashEscapeCharacter(data.consumeBoolean())
            );
        } catch (JSQLParserException e) {
        }

        try {
            CCJSqlParserUtil.parseAST(ast);
        } catch (JSQLParserException e) {
        }

        try {
            CCJSqlParserUtil.parseExpression(
                    expression,
                    data.consumeBoolean(),
                    parser -> parser
                            .withSquareBracketQuotation(data.consumeBoolean())
                            .withAllowComplexParsing(data.consumeBoolean())
                            .withUnsupportedStatements(data.consumeBoolean())
                            .withBackslashEscapeCharacter(data.consumeBoolean())
            );
        } catch (JSQLParserException e) {
        } catch (ArrayIndexOutOfBoundsException | TokenMgrException e) {
            // Needed to catch to enable fuzzer to continue
        }

        try {
            CCJSqlParserUtil.parseCondExpression(
                    condExp,
                    data.consumeBoolean(),
                    parser -> parser
                            .withSquareBracketQuotation(data.consumeBoolean())
                            .withAllowComplexParsing(data.consumeBoolean())
                            .withUnsupportedStatements(data.consumeBoolean())
                            .withBackslashEscapeCharacter(data.consumeBoolean())
            );
        } catch (JSQLParserException e) {
        } catch (ArrayIndexOutOfBoundsException | TokenMgrException e) {
            // Needed to catch to enable fuzzer to continue
        }
    }
}