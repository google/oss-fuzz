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

package org.apache.poi;

import com.code_intelligence.jazzer.api.FuzzedDataProvider;
import org.apache.poi.hssf.usermodel.HSSFEvaluationWorkbook;
import org.apache.poi.hssf.usermodel.HSSFWorkbook;
import org.apache.poi.ss.formula.FormulaParser;
import org.apache.poi.ss.formula.FormulaType;
import org.apache.poi.ss.formula.FormulaParseException;
import org.apache.poi.util.RecordFormatException;
import org.apache.poi.ooxml.POIXMLException;
import org.apache.poi.openxml4j.exceptions.OpenXML4JRuntimeException;

import java.nio.BufferUnderflowException;
import java.util.NoSuchElementException;

/**
 * Targeted fuzzer for the Apache POI Formula Parser.
 * This target was created to address low coverage in the formula parsing engine.
 */
public class FormulaParserFuzzer {
    private static HSSFWorkbook workbook;
    private static HSSFEvaluationWorkbook evalWorkbook;

    public static void fuzzerInitialize() {
        // Standard POI limit adjustment
        POIFuzzer.adjustLimits();
        
        workbook = new HSSFWorkbook();
        evalWorkbook = HSSFEvaluationWorkbook.create(workbook);
    }

    public static void fuzzerTestOneInput(FuzzedDataProvider data) {
        try {
            // Fuzz both FormulaType and the formula string
            FormulaType formulaType = data.pickValue(FormulaType.values());
            int sheetIndex = data.consumeInt(-1, 10);
            String formula = data.consumeRemainingAsString();
            
            if (formula == null || formula.isEmpty()) {
                return;
            }

            // Core parsing target
            FormulaParser.parse(formula, evalWorkbook, formulaType, sheetIndex);
            
        } catch (FormulaParseException | IllegalArgumentException | IllegalStateException | 
                 IndexOutOfBoundsException | ArithmeticException | NegativeArraySizeException |
                 RecordFormatException | BufferUnderflowException | OpenXML4JRuntimeException |
                 POIXMLException | UnsupportedOperationException | NoSuchElementException e) {
            // Expected exceptions on malformed formula syntax or internal state issues
        }
    }
}
