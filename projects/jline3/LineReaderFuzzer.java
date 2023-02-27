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
import org.jline.builtins.ConfigurationPath;
import org.jline.builtins.SyntaxHighlighter;
import org.jline.console.impl.SystemHighlighter;
import org.jline.reader.*;
import org.jline.reader.impl.DefaultHighlighter;
import org.jline.reader.impl.DefaultParser;
import org.jline.terminal.Size;
import org.jline.terminal.Terminal;
import org.jline.terminal.TerminalBuilder;

import java.lang.IllegalArgumentException;

import java.io.*;
import java.nio.file.Files;
import java.nio.file.Path;

public class LineReaderFuzzer {
    public static void fuzzerTestOneInput(FuzzedDataProvider data) {
        InputStream in = new ByteArrayInputStream(data.consumeBytes(500));
        OutputStream out = new ByteArrayOutputStream();
        Path nanorc;
        try {
            nanorc = LineReaderFuzzer.generateNanorcFile(data);
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
        SyntaxHighlighter syntaxHighlighter = SyntaxHighlighter.build(nanorc,data.consumeString(50));
        SyntaxHighlighter argsHighlighter = SyntaxHighlighter.build(nanorc,data.consumeString(50));
        SyntaxHighlighter groovyHighlighter = SyntaxHighlighter.build(nanorc,data.consumeString(50));

        SystemHighlighter highlighter = new SystemHighlighter(syntaxHighlighter, argsHighlighter, groovyHighlighter);
        highlighter.addFileHighlight(data.consumeString(50), data.consumeString(50));

        try {
            Terminal terminal = TerminalBuilder.builder()
                    .system(data.consumeBoolean())
                    .streams(in, out)
                    .name(data.consumeString(100))
                    .jna(data.consumeBoolean())
                    .build();
            terminal.setSize(new Size(data.consumeInt(0, 1000), data.consumeInt(0, 1000)));

            LineReader reader = LineReaderBuilder.builder()
                    .terminal(terminal)
                    .highlighter(highlighter)
                    .parser(new DefaultParser())
                    .variable(data.consumeString(50), data.consumeString(50))
                    .build();

            reader.readLine(data.consumeString(500), data.consumeChar());
        } catch (IOException | EndOfFileException | IllegalArgumentException | UserInterruptException e) {}
    }

    public static Path generateNanorcFile(FuzzedDataProvider data) throws IOException {
        Path nanorc = Files.createTempFile("nanorc", "");
        Files.write(nanorc, data.consumeBytes(500));
        return nanorc;
    }
}
