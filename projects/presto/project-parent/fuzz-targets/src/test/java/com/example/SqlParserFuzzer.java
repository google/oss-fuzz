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

import java.util.logging.LogManager;
import java.lang.ClassCastException;
import com.facebook.presto.sql.parser.*;
import com.facebook.presto.sql.parser.ParsingOptions;
import com.facebook.presto.sql.tree.Query;
import com.facebook.presto.sql.parser.ParsingException;
import org.junit.jupiter.api.BeforeAll;

import static com.facebook.presto.sql.parser.ParsingOptions.DecimalLiteralTreatment.AS_DOUBLE;
import static com.facebook.presto.sql.parser.ParsingOptions.DecimalLiteralTreatment.AS_DECIMAL;
import static com.facebook.presto.sql.parser.ParsingOptions.DecimalLiteralTreatment.REJECT;


class SqlParserFuzzer {
    static ParsingOptions.DecimalLiteralTreatment [] decimalLiteralTreatment = {
        AS_DOUBLE,
        AS_DECIMAL,
        REJECT
    };

    @BeforeAll
    static void setUp() {
        LogManager.getLogManager().reset();
    }

    @FuzzTest
    void myFuzzTest(FuzzedDataProvider data) {
        SqlParser parser = new SqlParser();
        ParsingOptions parsingOptions = ParsingOptions.builder().setDecimalLiteralTreatment(data.pickValue(decimalLiteralTreatment)).build();
        String sql = data.consumeRemainingAsString();

        try {
            parser.createStatement(sql, parsingOptions);
            parser.createExpression(sql, parsingOptions);
        } catch (ParsingException e) {
        }
    }
}