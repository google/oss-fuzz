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
import org.jxls.common.Context;
import org.jxls.common.JxlsException;
import org.jxls.util.CannotOpenWorkbookException;
import org.jxls.util.JxlsHelper;
import org.apache.poi.ss.usermodel.Workbook;
import org.apache.poi.ss.usermodel.Cell;
import org.apache.poi.ss.usermodel.Row;
import org.apache.poi.xssf.usermodel.XSSFSheet;
import org.apache.poi.xssf.usermodel.XSSFWorkbook;
import org.apache.poi.ss.usermodel.Comment;
import org.apache.poi.ss.usermodel.RichTextString;
import org.apache.poi.ss.usermodel.ClientAnchor;
import org.apache.poi.ss.usermodel.CreationHelper;
import org.apache.poi.ss.usermodel.Drawing;

import java.io.*;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.*;

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

    public static void fuzzerTestOneInput(FuzzedDataProvider data) {
        Path templatePath = null;
        try {
            templatePath = ProcessTemplateFuzzer.createDocument(data);
        } catch (IOException | IllegalArgumentException e) {
            return;
        }

        Context context = new Context(ProcessTemplateFuzzer.generateHashMap(data));
        OutputStream os = new ByteArrayOutputStream();
        InputStream in = null;
        try {
            in = Files.newInputStream(templatePath.toFile().toPath());
        } catch (IOException e) {
            throw new RuntimeException(e);
        }

        try {
            if (data.consumeBoolean()) {
                JxlsHelper.getInstance().processTemplate(in, os, context);
            } else {
                JxlsHelper.getInstance().processGridTemplateAtCell(
                    in,
                    os,
                    context,
                    data.consumeString(50),
                    data.consumeString(50)
                );
            }
        } catch (IOException | JxlsException e) {}
    }
}
