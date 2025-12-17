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

import java.io.File;
import java.nio.file.Paths;
import java.nio.file.Files;
import java.util.logging.LogRecord;
import java.util.logging.Level;

import org.apache.juli.FileHandler;
import org.apache.juli.OneLineFormatter;
import org.apache.juli.VerbatimFormatter;


public class FileHandlerFuzzer {
    static final String PREFIX = "test";
    static final String SUFFIX = ".log";
    // Use /tmp to avoid creating directories in /out which breaks check_build
    static final String logsBase = "/tmp/juli_fuzz_tests";
    static File logsDir = null;
    static FileHandler fh1 = null;
    static OneLineFormatter olf = new OneLineFormatter();
    static VerbatimFormatter vf = new VerbatimFormatter();
    static Level[] la = {Level.SEVERE, Level.WARNING, Level.INFO, Level.CONFIG, Level.FINE, Level.FINER, Level.FINEST, Level.ALL};
    static boolean initialized = false;

    public static void fuzzerTearDown() {
        if (fh1 != null) {
            try {
                fh1.close();
            } catch (Exception e) {
                // Ignore cleanup errors
            }
            fh1 = null;
        }
        if (logsDir != null) {
            deleteDirectory(logsDir);
            logsDir = null;
        }
        initialized = false;
    }

    public static void fuzzerInitialize() {
        try {
            if (Files.exists(Paths.get(logsBase))) {
                deleteDirectory(new File(logsBase));
            }
            new File(logsBase).mkdirs();
            logsDir = new File(logsBase);
            // Only use FileHandler (not AsyncFileHandler) to avoid threading issues
            fh1 = new FileHandler(logsDir.getAbsolutePath(), PREFIX, SUFFIX);
            fh1.open();
            initialized = true;
        } catch (Exception e) {
            // If initialization fails, mark as initialized to avoid retry loops
            initialized = true;
        }
    }

    public static void fuzzerTestOneInput(FuzzedDataProvider data) {
        if (!initialized) {
            fuzzerInitialize();
        }
        
        // Skip if handler failed to initialize
        if (fh1 == null) {
            return;
        }

        int fn = data.consumeInt(0, 2);
        int ln = data.consumeInt(0, la.length - 1);
        String str = data.consumeRemainingAsString();

        switch (fn) {
            case 1:
                fh1.setFormatter(olf);
                break;
            case 2:
                fh1.setFormatter(vf);
                break;
            default:
                break;
        }

        fh1.setLevel(la[ln]);
        
        LogRecord lr = new LogRecord(la[ln], str);
        
        try {
            fh1.publish(lr);
            fh1.flush();
        } catch (Exception e) {
            // Ignore publish errors
        }
    }

    static boolean deleteDirectory(File directoryToBeDeleted) {
        if (directoryToBeDeleted == null || !directoryToBeDeleted.exists()) {
            return true;
        }
        File[] allContents = directoryToBeDeleted.listFiles();
        if (allContents != null) {
            for (File file : allContents) {
                deleteDirectory(file);
            }
        }
        return directoryToBeDeleted.delete();
    }
}