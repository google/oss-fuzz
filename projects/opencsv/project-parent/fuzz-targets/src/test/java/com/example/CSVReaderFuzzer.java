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

import com.opencsv.*;
import com.opencsv.enums.CSVReaderNullFieldIndicator;
import com.opencsv.exceptions.CsvException;
import com.opencsv.exceptions.CsvMultilineLimitBrokenException;
import com.opencsv.exceptions.CsvValidationException;
import org.apache.commons.lang3.StringUtils;
import org.junit.jupiter.api.*;

import java.io.FileReader;
import java.io.IOException;
import java.io.StringReader;
import java.util.Locale;
import java.util.regex.PatternSyntaxException;

class CSVReaderFuzzer {
    static CSVParser csvParser;
    static Locale systemLocale;

    @BeforeAll
    static void storeSystemLocale() {
        systemLocale = Locale.getDefault();
    }

    @FuzzTest
    void myFuzzTest(FuzzedDataProvider data) {
        try {
            Locale.setDefault(data.pickValue(Locale.getAvailableLocales()));
            csvParser = new CSVParser();
            ICSVParser parser = new CSVParserBuilder()
                    .withEscapeChar(data.consumeChar())
                    .withFieldAsNull(data.pickValue(CSVReaderNullFieldIndicator.values()))
                    .withIgnoreLeadingWhiteSpace(data.consumeBoolean())
                    .withIgnoreQuotations(data.consumeBoolean())
                    .withQuoteChar(data.consumeChar())
                    .withSeparator(data.consumeChar())
                    .withStrictQuotes(data.consumeBoolean())
                    .build();

            RFC4180Parser rfc4180Parser = new RFC4180ParserBuilder()
                    .withFieldAsNull(data.pickValue(CSVReaderNullFieldIndicator.values()))
                    .withQuoteChar(data.consumeChar())
                    .withSeparator(data.consumeChar())
                    .build();

            ICSVParser [] icsvParsers = {csvParser, parser, rfc4180Parser};
            CSVReader csvReader = new CSVReaderBuilder(new StringReader(data.consumeString(500)))
                    .withCSVParser(data.pickValue(icsvParsers))
                    .withFieldAsNull(data.pickValue(CSVReaderNullFieldIndicator.values()))
                    .withKeepCarriageReturn(data.consumeBoolean())
                    .build();
            csvReader.readAll();

            Locale.setDefault(systemLocale);
        } catch (CsvException | IOException e) {
            // Documented exceptions.
        } catch (UnsupportedOperationException | PatternSyntaxException e) {
            // Need to catch them to continue fuzzing.
        }

    }
}