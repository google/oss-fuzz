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
import com.fasterxml.jackson.databind.MapperFeature;
import com.fasterxml.jackson.databind.SerializationFeature;
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
import java.lang.ArrayIndexOutOfBoundsException;
import java.lang.IllegalArgumentException;
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
        try {
            List<Problem> problems = Roaster.validateSnippet(classString);
            if (problems.size()>0) {
                return;
            }            
        } catch (ArrayIndexOutOfBoundsException e) {
            return;
        }

        MapperFeature[] mapperfeatures = new MapperFeature[]{MapperFeature.AUTO_DETECT_CREATORS,
                                        MapperFeature.AUTO_DETECT_FIELDS,
                                        MapperFeature.AUTO_DETECT_GETTERS,
                                        MapperFeature.AUTO_DETECT_IS_GETTERS,
                                        MapperFeature.AUTO_DETECT_SETTERS,
                                        MapperFeature.REQUIRE_SETTERS_FOR_GETTERS,
                                        MapperFeature.USE_GETTERS_AS_SETTERS,
                                        MapperFeature.INFER_CREATOR_FROM_CONSTRUCTOR_PROPERTIES,
                                        MapperFeature.INFER_PROPERTY_MUTATORS,
                                        MapperFeature.ALLOW_FINAL_FIELDS_AS_MUTATORS,
                                        MapperFeature.ALLOW_VOID_VALUED_PROPERTIES,
                                        MapperFeature.CAN_OVERRIDE_ACCESS_MODIFIERS,
                                        MapperFeature.OVERRIDE_PUBLIC_ACCESS_MODIFIERS,
                                        MapperFeature.SORT_PROPERTIES_ALPHABETICALLY,
                                        MapperFeature.USE_WRAPPER_NAME_AS_PROPERTY_NAME,
                                        MapperFeature.ACCEPT_CASE_INSENSITIVE_ENUMS,
                                        MapperFeature.ACCEPT_CASE_INSENSITIVE_ENUMS,
                                        MapperFeature.ACCEPT_CASE_INSENSITIVE_PROPERTIES,
                                        MapperFeature.ACCEPT_CASE_INSENSITIVE_VALUES,
                                        MapperFeature.ALLOW_EXPLICIT_PROPERTY_RENAMING,
                                        MapperFeature.USE_STD_BEAN_NAMING,
                                        MapperFeature.ALLOW_COERCION_OF_SCALARS,
                                        MapperFeature.DEFAULT_VIEW_INCLUSION,
                                        MapperFeature.IGNORE_DUPLICATE_MODULE_REGISTRATIONS,
                                        MapperFeature.IGNORE_MERGE_FOR_UNMERGEABLE,
                                        MapperFeature.USE_BASE_TYPE_AS_DEFAULT_IMPL,
                                        MapperFeature.USE_STATIC_TYPING,
                                        MapperFeature.BLOCK_UNSAFE_POLYMORPHIC_BASE_TYPES};

        SerializationFeature[] serializationfeatures = new SerializationFeature[]{SerializationFeature.INDENT_OUTPUT,
                                        SerializationFeature.CLOSE_CLOSEABLE,
                                        SerializationFeature.WRAP_ROOT_VALUE,
                                        SerializationFeature.WRITE_DATE_KEYS_AS_TIMESTAMPS,
                                        SerializationFeature.WRITE_CHAR_ARRAYS_AS_JSON_ARRAYS,
                                        SerializationFeature.WRITE_ENUMS_USING_TO_STRING,
                                        SerializationFeature.WRITE_ENUMS_USING_INDEX,
                                        SerializationFeature.WRITE_SINGLE_ELEM_ARRAYS_UNWRAPPED,
                                        SerializationFeature.WRITE_BIGDECIMAL_AS_PLAIN,
                                        SerializationFeature.ORDER_MAP_ENTRIES_BY_KEYS,
                                        SerializationFeature.USE_EQUALITY_FOR_OBJECT_ID,
                                        SerializationFeature.FAIL_ON_EMPTY_BEANS,
                                        SerializationFeature.WRAP_EXCEPTIONS,
                                        SerializationFeature.FLUSH_AFTER_WRITE_VALUE,
                                        SerializationFeature.WRITE_DATES_AS_TIMESTAMPS,
                                        SerializationFeature.WRITE_NULL_MAP_VALUES,
                                        SerializationFeature.WRITE_EMPTY_JSON_ARRAYS,
                                        SerializationFeature.WRITE_DATE_TIMESTAMPS_AS_NANOSECONDS,
                                        SerializationFeature.EAGER_SERIALIZER_FETCH};

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

        for (int i = 0; i < mapperfeatures.length; i++) {
            if (data.consumeBoolean()) {
                mapper.enable(mapperfeatures[i]);
            } else {
                mapper.disable(mapperfeatures[i]);
            }
        }

        for (int i = 0; i < serializationfeatures.length; i++) {
            if (data.consumeBoolean()) {
                mapper.enable(serializationfeatures[i]);
            } else {
                mapper.disable(serializationfeatures[i]);
            }
        }

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
            } catch (IOException | ClassNotFoundException | IllegalArgumentException e) {
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