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

import java.io.*;
import java.util.Locale;
import tech.tablesaw.io.csv.*;
import tech.tablesaw.api.Table;
import tech.tablesaw.io.AddCellToColumnException;
import tech.tablesaw.io.fixed.FixedWidthReadOptions;
import tech.tablesaw.io.ColumnIndexOutOfBoundsException;


class ReaderFuzzer {
    @FuzzTest
    void myFuzzTest(FuzzedDataProvider data) {
        boolean b1 = data.consumeBoolean();
        boolean b2 = data.consumeBoolean();
        boolean b3 = data.consumeBoolean();
        boolean b4 = data.consumeBoolean();
        boolean b5 = data.consumeBoolean();
        char c1 = data.consumeChar();
        Locale locale = data.pickValue(Locale.getAvailableLocales());
        Reader reader = new StringReader(data.consumeString(4096));

        CsvReadOptions options =
                CsvReadOptions.builder(reader)
                        .allowDuplicateColumnNames(b1)
                        .minimizeColumnSizes()
                        .ignoreZeroDecimal(b2)
                        .locale(locale)
                        .separator(c1)
                        .header(b3)
                        .sample(b4)
                        .build();

        FixedWidthReadOptions options1 =
                FixedWidthReadOptions.builder(reader)
                        .skipTrailingCharsUntilNewline(b1)
                        .minimizeColumnSizes()
                        .ignoreZeroDecimal(b2)
                        .systemLineEnding()
                        .locale(locale)
                        .padding(c1)
                        .header(b3)
                        .sample(b4)
                        .build();

        try {
            Table table = Table.read().usingOptions(b5 ? options : options1);
            table.smile().toDataFrame();
            table.print();
        } catch (NullPointerException | IllegalArgumentException | ArrayIndexOutOfBoundsException |
            ColumnIndexOutOfBoundsException | AddCellToColumnException | IllegalStateException e) {
            // Need to catch these exceptions to reach interesting findings.
        }
    }
}
