// Copyright 2022 Google LLC
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
import com.code_intelligence.jazzer.api.FuzzerSecurityIssueLow;

import java.io.File;
import java.nio.file.Paths;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.nio.file.FileSystems;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.charset.StandardCharsets;
import java.time.LocalDate;
import java.time.LocalDateTime;
import java.util.TooManyListenersException;
import java.util.logging.LogRecord;
import java.util.logging.Level;

import org.apache.juli.FileHandler;
import org.apache.juli.AsyncFileHandler;
import org.apache.juli.JdkLoggerFormatter;
import org.apache.juli.OneLineFormatter;
import org.apache.juli.VerbatimFormatter;


public class FileHandlerFuzzer {
    static String PREFIX = "test";
    static String SUFFIX = ".log";
    static String logsBase = "./juli_tests";
    static File logsDir;
    static int cnt = Integer.MIN_VALUE;
    static FileHandler fh1 = null;
    static AsyncFileHandler afh1 = null;
    static JdkLoggerFormatter jlf = new JdkLoggerFormatter();
    static OneLineFormatter olf = new OneLineFormatter();
    static VerbatimFormatter vf = new VerbatimFormatter();
    static java.util.logging.Level [] la = {Level.SEVERE, Level.WARNING, Level.INFO, Level.CONFIG, Level.FINE, Level.FINER, Level.FINEST, Level.ALL};
    static String [] ea = {StandardCharsets.ISO_8859_1.name(), StandardCharsets.US_ASCII.name(), StandardCharsets.UTF_16.name(), 
        StandardCharsets.UTF_16BE.name(), StandardCharsets.UTF_16LE.name(), StandardCharsets.UTF_8.name()};

    public static void fuzzerTearDown() {
        assert deleteDirectory(logsDir) == true : new FuzzerSecurityIssueLow("Delete Error in fuzzerTearDown!");
    }

    public static void fuzzerInitialize() {
        if (Files.exists(Paths.get(logsBase))) {
            assert deleteDirectory(new File(logsBase)) == true : new FuzzerSecurityIssueLow("Delete Error in fuzzerInitialize!");
        }
    }

    public static void fuzzerTestOneInput(FuzzedDataProvider data) {
        new File(logsBase).mkdirs();

        logsDir = new File(logsBase);

        fh1 = new FileHandler(logsDir.getAbsolutePath(), PREFIX, SUFFIX);

        afh1 = new AsyncFileHandler(logsDir.getAbsolutePath(), PREFIX, SUFFIX);
        
        int fn = data.consumeInt(0, 3);
        int ln = data.consumeInt(0, la.length - 1);
        int en = data.consumeInt(0, ea.length - 1);
        String str = data.consumeRemainingAsString();

        switch (fn) {
            case 0:
                // fh1.setFormatter(jlf);
                // afh1.setFormatter(jlf);
                break;
            case 1:
                fh1.setFormatter(olf);
                afh1.setFormatter(olf);
                break;
            case 2:
                fh1.setFormatter(vf);
                afh1.setFormatter(vf);
                break;
            case 3:
                break;
            default:
                break;
        }

        fh1.setLevel(la[ln]);
        afh1.setLevel(la[ln]);

        try {
            fh1.setEncoding(ea[en]);
            afh1.setEncoding(ea[en]);   
        } catch (UnsupportedEncodingException e) {
            throw new FuzzerSecurityIssueLow("UnsupportedEncodingException Error!");
        }
        
        fh1.open();
        afh1.open();
        LogRecord lr = new LogRecord(la[ln], str);
        
        try {
            fh1.publish(lr);
            afh1.publish(lr);
        } catch (Exception e) {
        }

        fh1.flush();
        afh1.flush();
        fh1.close();
        afh1.close();

        if (cnt++ % 1000 == 0) {
            assert deleteDirectory(logsDir) == true : new FuzzerSecurityIssueLow("Delete Error!");
        }
    }

    static boolean deleteDirectory(File directoryToBeDeleted) {
        File[] allContents = directoryToBeDeleted.listFiles();
        if (allContents != null) {
            for (File file : allContents) {
                deleteDirectory(file);
            }
        }
        return directoryToBeDeleted.delete();
    }

}