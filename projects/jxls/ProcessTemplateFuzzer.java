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

import com.code_intelligence.jazzer.api.FuzzedDataProvider;
import org.apache.poi.ss.usermodel.*;
import org.apache.poi.xssf.usermodel.XSSFSheet;
import org.apache.poi.xssf.usermodel.XSSFWorkbook;
import org.jxls.builder.JxlsOutputFile;
import org.jxls.transform.poi.JxlsPoiTemplateFillerBuilder;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.file.Path;
import java.util.HashMap;
import java.util.Map;

public class ProcessTemplateFuzzer {
    private static Path templatePath;

    public static void fuzzerInitialize() throws IOException {
        templatePath = new File("/out/template.xlsx").toPath();
        templatePath.toFile().createNewFile();
    }

    private static Map<String, Object> generateHashMap(FuzzedDataProvider data) {
        Map<String, Object> model = new HashMap<String, Object>();
        for (int i = 0; i <= data.consumeInt(0, 10); i++) {
            model.put(data.consumeString(50), data.consumeBytes(200));
        }

        return model;
    }

    public static Comment generateComment(XSSFSheet sheet, CreationHelper factory, FuzzedDataProvider data) {
        ClientAnchor anchor = factory.createClientAnchor();
        Drawing drawing = sheet.createDrawingPatriarch();
        Comment comment = drawing.createCellComment(anchor);
        comment.setString(factory.createRichTextString(data.consumeString(200)));
        comment.setAuthor(data.consumeString(100));
        return comment;
    }

    public static Path createDocument(FuzzedDataProvider data) throws IOException {
        XSSFWorkbook workbook = new XSSFWorkbook();
        XSSFSheet sheet = workbook.createSheet(data.consumeString(50));
        CreationHelper factory = workbook.getCreationHelper();

        for (int i = 0; i < data.consumeInt(0, 50); i++) {
            Row row = sheet.createRow(i);
            for (int j = 0; j < data.consumeInt(0, 50); j++) {
                Cell cell = row.createCell(j);
                cell.setCellValue(data.consumeString(200));

                if (data.consumeBoolean()) {
                    cell.setCellComment(ProcessTemplateFuzzer.generateComment(sheet, factory, data));
                }
            }
        }

        FileOutputStream out = new FileOutputStream(templatePath.toFile());
        workbook.write(out);
        out.close();

        return templatePath;
    }

    public static void fuzzerTestOneInput(FuzzedDataProvider data) throws FileNotFoundException {
        Path templatePath;
        try {
            templatePath = ProcessTemplateFuzzer.createDocument(data);
        } catch (IOException | IllegalArgumentException e) {
            return;
        }


        Map<String, Object> dataMap = ProcessTemplateFuzzer.generateHashMap(data);

        File output = new File("report.xlsx");

        JxlsPoiTemplateFillerBuilder.newInstance()
                .withTemplate(templatePath.toFile())
                .build()
                .fill(dataMap, new JxlsOutputFile(output));

    }
}
