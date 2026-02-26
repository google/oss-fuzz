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

import com.code_intelligence.jazzer.api.FuzzedDataProvider;
import org.apache.poi.hssf.usermodel.HSSFEvaluationWorkbook;
import org.apache.poi.hssf.usermodel.HSSFWorkbook;
import org.apache.poi.hssf.usermodel.HSSFSheet;
import org.apache.poi.hssf.usermodel.HSSFRow;
import org.apache.poi.hssf.usermodel.HSSFCell;
import org.apache.poi.ss.formula.WorkbookEvaluator;
import org.apache.poi.ss.formula.EvaluationCell;
import org.apache.poi.ss.formula.FormulaParseException;
import org.apache.poi.ss.formula.eval.NotImplementedException;
import org.apache.poi.ss.usermodel.FormulaError;
import org.apache.poi.util.RecordFormatException;

public class WorkbookEvaluatorFuzzer {
    private static HSSFWorkbook workbook;
    private static HSSFSheet sheet;
    private static HSSFCell fuzzerCell;
    private static HSSFEvaluationWorkbook evalWorkbook;
    private static EvaluationCell fuzzerEvalCell;
    private static WorkbookEvaluator evaluator;

    private static final String[] EXCEL_FUNCTIONS = {
        "SUM(", "IF(", "VLOOKUP(", "HLOOKUP(", "INDEX(", "MATCH(", "OFFSET(", "INDIRECT(", 
        "CHOOSE(", "ADDRESS(", "AREAS(", "CELL(", "COLUMN(", "COLUMNS(", "ROW(", "ROWS(",
        "SUMPRODUCT(", "SUMIFS(", "COUNTIFS(", "AVERAGEIFS(", "MAXIFS(", "MINIFS(",
        "NPV(", "XIRR(", "PMT(", "FV(", "IRR(", "MIRR(", "NPER(", "RATE(",
        "DGET(", "DSUM(", "DAVERAGE(", "DCOUNT(", "DMAX(", "DMIN(", "DPRODUCT(",
        "AND(", "OR(", "NOT(", "XOR(", "IFERROR(", "IFNA(", "SWITCH(",
        "CONCATENATE(", "TEXTJOIN(", "MID(", "LEFT(", "RIGHT(", "FIND(", "SEARCH(", "SUBSTITUTE(",
        "DATE(", "TIME(", "NOW(", "TODAY(", "DATEDIF(", "WORKDAY(", "NETWORKDAYS("
    };

    public static void fuzzerInitialize() {
        workbook = new HSSFWorkbook();
        sheet = workbook.createSheet("FuzzSheet");
        
        // Target Cell for the fuzzer (A1)
        HSSFRow fuzzerRow = sheet.createRow(0);
        fuzzerCell = fuzzerRow.createCell(0);

        // Pre-populate a 20x20 grid with data for referential formulas (SUM, MATCH, etc.)
        for (int r = 1; r <= 20; r++) {
            HSSFRow row = sheet.createRow(r);
            for (int c = 0; c < 20; c++) {
                HSSFCell dataCell = row.createCell(c);
                switch ((r + c) % 5) {
                    case 0: dataCell.setCellValue(42.0 * r); break;
                    case 1: dataCell.setCellValue(-r * 1.5); break;
                    case 2: dataCell.setCellValue("Data" + c); break;
                    case 3: dataCell.setCellValue((r % 2 == 0)); break;
                    case 4: dataCell.setCellErrorValue(FormulaError.VALUE.getCode()); break;
                }
            }
        }
        
        evalWorkbook = HSSFEvaluationWorkbook.create(workbook);
        evaluator = new WorkbookEvaluator(evalWorkbook, null, null);
        fuzzerEvalCell = evalWorkbook.getSheet(0).getCell(0, 0); // Pointer to A1 wrapper
    }

    public static void fuzzerTestOneInput(FuzzedDataProvider data) {
        try {
            StringBuilder sb = new StringBuilder();
            if (data.consumeBoolean()) { 
                sb.append(data.pickValue(EXCEL_FUNCTIONS));
            }
            sb.append(data.consumeRemainingAsString());
            if (data.consumeBoolean()) {
                sb.append(")");
            }
            
            String formula = sb.toString();
            if (formula.isEmpty()) return;

            // 1. Compile. Swallow Parser RuntimeExceptions per POI security policy.
            try {
                fuzzerCell.setCellFormula(formula);
            } catch (Exception e) {
                return; 
            }
            
            // 2. Target the evaluation engine directly
            evaluator.evaluate(fuzzerEvalCell);
            
        } catch (Exception e) {
            // Filter expected engine/logic limitations
            if (e instanceof IllegalArgumentException || 
                e instanceof IllegalStateException ||
                e instanceof FormulaParseException ||
                e instanceof NotImplementedException ||
                e instanceof RecordFormatException) {
                return;
            }
            // FATAL: Evaluation engine crashed internally (NPE, OOB, etc.)
            throw new RuntimeException("Found a viable flaw in the EVALUATOR engine!", e);
        }
    }
}
