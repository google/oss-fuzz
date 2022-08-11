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

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectReader;
import com.fasterxml.jackson.core.JsonFactory;
import com.fasterxml.jackson.core.JsonParser;

import java.io.*;
import java.util.*;
import java.util.Arrays; 
import java.lang.NoSuchMethodException;
import java.lang.IllegalAccessException;
import java.lang.ClassNotFoundException;
import java.lang.reflect.*;
import java.lang.reflect.Method; 
import java.net.URL; 
import java.net.URLClassLoader; 
 
import javax.tools.JavaCompiler; 
import javax.tools.JavaFileObject; 
import javax.tools.StandardJavaFileManager; 
import javax.tools.StandardLocation; 
import javax.tools.ToolProvider;

import org.jboss.forge.roaster.Roaster;
import org.jboss.forge.roaster.Problem;

import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;


public class ObjectReaderRandomClassFuzzer {
    public static void fuzzerTestOneInput(FuzzedDataProvider data) {
        String classString = data.consumeString(1000000);

        // Sanity check: Do we have valid java code? If not, exit early.
        List<Problem> problems = Roaster.validateSnippet(classString);
        if (problems.size()>0) {
            return;
        }

        DeserializationFeature[] deserializationfeatures = new DeserializationFeature[]{DeserializationFeature.USE_BIG_DECIMAL_FOR_FLOATS,
                                        DeserializationFeature.USE_BIG_INTEGER_FOR_INTS,
                                        DeserializationFeature.USE_JAVA_ARRAY_FOR_JSON_ARRAY,
                                        DeserializationFeature.READ_ENUMS_USING_TO_STRING,
                                        DeserializationFeature.ACCEPT_SINGLE_VALUE_AS_ARRAY,
                                        DeserializationFeature.UNWRAP_ROOT_VALUE,
                                        DeserializationFeature.UNWRAP_SINGLE_VALUE_ARRAYS,
                                        DeserializationFeature.ACCEPT_EMPTY_ARRAY_AS_NULL_OBJECT,
                                        DeserializationFeature.ACCEPT_EMPTY_STRING_AS_NULL_OBJECT,
                                        DeserializationFeature.ACCEPT_FLOAT_AS_INT,
                                        DeserializationFeature.ADJUST_DATES_TO_CONTEXT_TIME_ZONE,
                                        DeserializationFeature.READ_DATE_TIMESTAMPS_AS_NANOSECONDS,
                                        DeserializationFeature.READ_UNKNOWN_ENUM_VALUES_AS_NULL,
                                        DeserializationFeature.READ_UNKNOWN_ENUM_VALUES_USING_DEFAULT_VALUE,
                                        DeserializationFeature.FAIL_ON_IGNORED_PROPERTIES,
                                        DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES,
                                        DeserializationFeature.FAIL_ON_INVALID_SUBTYPE,
                                        DeserializationFeature.FAIL_ON_NULL_FOR_PRIMITIVES,
                                        DeserializationFeature.FAIL_ON_NUMBERS_FOR_ENUMS,
                                        DeserializationFeature.FAIL_ON_READING_DUP_TREE_KEY,
                                        DeserializationFeature.FAIL_ON_UNRESOLVED_OBJECT_IDS,
                                        DeserializationFeature.FAIL_ON_MISSING_CREATOR_PROPERTIES,
                                        DeserializationFeature.WRAP_EXCEPTIONS,
                                        DeserializationFeature.FAIL_ON_TRAILING_TOKENS,
                                        DeserializationFeature.EAGER_DESERIALIZER_FETCH};

        URLClassLoader classLoader;
        File sourceFile;
        String classname;
        File parentDirectory;
        Class<?> randomClass;
        boolean doThis;
        byte[] fileData;
        int fuzzInt1, fuzzInt2;
        FileOutputStream out;
        Object o;
        Reader stringR;
        ObjectReader r, r2, r3;
        JsonParser jp;

        ObjectMapper mapper = new ObjectMapper();

        try {
            ///////////////////////////
            // Create a random class //
            ///////////////////////////

            // create an empty source file 
            sourceFile = File.createTempFile("RandomFuzz", ".java"); 
            sourceFile.deleteOnExit();
     
            // generate the source code, using the source filename as the class name
            classname = sourceFile.getName().split("\\.")[0]; 
            String sourceCode = "public class " + classname + "{" + classString + "}";
     
            // write the source code into the source file
            FileWriter writer = new FileWriter(sourceFile);
            writer.write(sourceCode); 
            writer.close(); 
             
            // compile the source file 
            JavaCompiler compiler = ToolProvider.getSystemJavaCompiler();
            StandardJavaFileManager fileManager = compiler.getStandardFileManager(null, null, null);
            parentDirectory = sourceFile.getParentFile(); 
            fileManager.setLocation(StandardLocation.CLASS_OUTPUT, Arrays.asList(parentDirectory)); 
            Iterable<? extends JavaFileObject> compilationUnits = fileManager.getJavaFileObjectsFromFiles(Arrays.asList(sourceFile));
            compiler.getTask(null, fileManager, null, null, null, compilationUnits).call(); 
            fileManager.close(); 
        } catch (IOException e) {
            // We have't got a valid class. Don't procced.
            return;
        }
        try {
            // load the compiled class
            classLoader = URLClassLoader.newInstance(new URL[] { parentDirectory.toURI().toURL() });
            try {
                randomClass = classLoader.loadClass(classname);
                r = mapper.readerFor(randomClass);

                // set reader settings
                for (int i = 0; i < deserializationfeatures.length; i++) {
                    if (data.consumeBoolean()) {
                        r = r.with(deserializationfeatures[i]);
                    } else {
                        r = r.without(deserializationfeatures[i]);
                    }
                }

                // Select an API and call it
                int callType = data.consumeInt();
                switch (callType%19) {
                case 0:
                    r.readValue(data.consumeRemainingAsString());
                case 1:
                    r.readValue(data.consumeRemainingAsBytes());
                case 2:
                    r.readTree(data.consumeRemainingAsString());
                case 3:
                    r.readTree(data.consumeRemainingAsBytes());
                case 4:
                    doThis = data.consumeBoolean();
                    jp = r.createParser(data.consumeRemainingAsBytes());
                    o = r.readValue(jp);
                    if (doThis) {
                        r3 = r.withValueToUpdate(o);
                    }
                case 5:
                    stringR = new StringReader(new String(data.consumeRemainingAsBytes()));
                    r.readValue(stringR);
                case 6:
                    stringR = new StringReader(new String(data.consumeRemainingAsBytes()));
                    r.readValues(stringR);
                case 7:
                    r.readValues(data.consumeRemainingAsString());
                case 8:
                    r.readValue(data.consumeRemainingAsBytes());
                case 9:
                    doThis = data.consumeBoolean();
                    jp = r.createParser(data.consumeRemainingAsBytes());
                    o = r.readValues(jp);
                    if (doThis) {
                        r3 = r.withValueToUpdate(o);
                    }
                case 10:
                    doThis = data.consumeBoolean();
                    jp = r.createParser(data.consumeRemainingAsBytes());
                    o = r.readTree(jp);
                    if (doThis) {
                        r3 = r.withValueToUpdate(o);
                    }
                case 11:
                    stringR = new StringReader(new String(data.consumeRemainingAsBytes()));
                    r.readTree(stringR);
                case 12:
                    fileData = data.consumeRemainingAsBytes();
                    out = new FileOutputStream("fuzzFile");
                    out.write(fileData);
                    out.close();
                    r.readValue(new File("fuzzFile"));
                case 13:
                    fileData = data.consumeRemainingAsBytes();
                    out = new FileOutputStream("fuzzFile");
                    out.write(fileData);
                    out.close();
                    r.readValues(new File("fuzzFile"));
                case 14:
                    fileData = data.consumeRemainingAsBytes();
                    out = new FileOutputStream("fuzzFile");
                    out.write(fileData);
                    out.close();
                    jp = r.createParser(new File("fuzzFile"));
                    o = r.readTree(jp);
                case 15:
                    fuzzInt1 = data.consumeInt();
                    fuzzInt2 = data.consumeInt();
                    r.readValue(data.consumeRemainingAsBytes(), fuzzInt1, fuzzInt2);
                case 16:
                    fuzzInt1 = data.consumeInt();
                    fuzzInt2 = data.consumeInt();
                    r.readValues(data.consumeRemainingAsBytes(), fuzzInt1, fuzzInt2);
                case 17:
                    fuzzInt1 = data.consumeInt();
                    fuzzInt2 = data.consumeInt();
                    r.readTree(data.consumeRemainingAsBytes(), fuzzInt1, fuzzInt2);
                case 18:
                    fuzzInt1 = data.consumeInt();
                    fuzzInt2 = data.consumeInt();
                    jp = r.createParser(data.consumeRemainingAsBytes(), fuzzInt1, fuzzInt2);
                }
            } catch (IOException | ClassNotFoundException e) {
                // Close the classLoader. This should render the
                // created class unusable.
                classLoader.close();
                return;
            }
        } catch (IOException e) {
           return;
        }
    }
}