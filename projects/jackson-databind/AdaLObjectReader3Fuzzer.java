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

import java.util.*;
import java.util.regex.Pattern;
import java.io.Reader;
import java.io.StringReader;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.FileOutputStream;
import java.nio.charset.Charset;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.io.File;
import java.io.InputStream;
import java.io.DataInput;
import java.io.EOFException;
import java.lang.IllegalArgumentException;
import java.net.URI;

import tools.jackson.databind.ObjectMapper;
import tools.jackson.databind.ObjectReader;
import tools.jackson.databind.DeserializationConfig;
import tools.jackson.databind.DeserializationFeature;
import tools.jackson.databind.MapperFeature;
import tools.jackson.databind.SerializationFeature;
import tools.jackson.databind.DefaultTyping;
import tools.jackson.core.JsonParser;
import tools.jackson.core.TreeNode;
import tools.jackson.databind.json.JsonMapper;
import tools.jackson.databind.node.ObjectNode;
import tools.jackson.databind.JsonNode;
import tools.jackson.core.json.JsonFactory;
import tools.jackson.core.JacksonException;

// For NoCheckSubTypeValidator
import tools.jackson.databind.JavaType;
import tools.jackson.databind.cfg.MapperConfig;
import tools.jackson.databind.DatabindContext;
import tools.jackson.databind.jsontype.PolymorphicTypeValidator;

public class AdaLObjectReader3Fuzzer {
    public static void fuzzerTestOneInput(FuzzedDataProvider data) {

        boolean doThis;
        byte[] fileData;
        int fuzzInt1, fuzzInt2;
        FileOutputStream out;
        Object o;
        Reader stringR;
        ObjectReader r, r2, r3;
        JsonParser jp;

        MapperFeature[] mapperfeatures = new MapperFeature[]{
            MapperFeature.USE_ANNOTATIONS,
            MapperFeature.USE_GETTERS_AS_SETTERS,
            MapperFeature.PROPAGATE_TRANSIENT_MARKER,
            MapperFeature.REQUIRE_SETTERS_FOR_GETTERS,
            MapperFeature.ALLOW_FINAL_FIELDS_AS_MUTATORS,
            MapperFeature.INFER_PROPERTY_MUTATORS,
            MapperFeature.INFER_CREATOR_FROM_CONSTRUCTOR_PROPERTIES,
            MapperFeature.ALLOW_VOID_VALUED_PROPERTIES,
            MapperFeature.CAN_OVERRIDE_ACCESS_MODIFIERS,
            MapperFeature.OVERRIDE_PUBLIC_ACCESS_MODIFIERS,
            MapperFeature.USE_STATIC_TYPING,
            MapperFeature.USE_BASE_TYPE_AS_DEFAULT_IMPL,
            MapperFeature.DEFAULT_VIEW_INCLUSION,
            MapperFeature.SORT_PROPERTIES_ALPHABETICALLY,
            MapperFeature.ACCEPT_CASE_INSENSITIVE_PROPERTIES,
            MapperFeature.ACCEPT_CASE_INSENSITIVE_ENUMS,
            MapperFeature.ACCEPT_CASE_INSENSITIVE_VALUES,
            MapperFeature.USE_WRAPPER_NAME_AS_PROPERTY_NAME,
            MapperFeature.ALLOW_EXPLICIT_PROPERTY_RENAMING,
            MapperFeature.ALLOW_COERCION_OF_SCALARS,
            MapperFeature.IGNORE_MERGE_FOR_UNMERGEABLE,
            MapperFeature.APPLY_DEFAULT_VALUES
        };

        SerializationFeature[] serializationfeatures = new SerializationFeature[]{
            SerializationFeature.WRAP_ROOT_VALUE,
            SerializationFeature.INDENT_OUTPUT,
            SerializationFeature.FAIL_ON_EMPTY_BEANS,
            SerializationFeature.FAIL_ON_SELF_REFERENCES,
            SerializationFeature.WRAP_EXCEPTIONS,
            SerializationFeature.CLOSE_CLOSEABLE,
            SerializationFeature.FLUSH_AFTER_WRITE_VALUE,
            SerializationFeature.WRITE_CHAR_ARRAYS_AS_JSON_ARRAYS,
            SerializationFeature.WRITE_EMPTY_JSON_ARRAYS,
            SerializationFeature.WRITE_SINGLE_ELEM_ARRAYS_UNWRAPPED,
            SerializationFeature.ORDER_MAP_ENTRIES_BY_KEYS,
            SerializationFeature.EAGER_SERIALIZER_FETCH,
            SerializationFeature.USE_EQUALITY_FOR_OBJECT_ID
        };

        DeserializationFeature[] deserializationfeatures = new DeserializationFeature[]{
            DeserializationFeature.USE_BIG_DECIMAL_FOR_FLOATS,
            DeserializationFeature.USE_BIG_INTEGER_FOR_INTS,
            DeserializationFeature.USE_LONG_FOR_INTS,
            DeserializationFeature.USE_JAVA_ARRAY_FOR_JSON_ARRAY,
            DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES,
            DeserializationFeature.FAIL_ON_NULL_FOR_PRIMITIVES,
            DeserializationFeature.FAIL_ON_INVALID_SUBTYPE,
            DeserializationFeature.FAIL_ON_READING_DUP_TREE_KEY,
            DeserializationFeature.FAIL_ON_IGNORED_PROPERTIES,
            DeserializationFeature.FAIL_ON_UNRESOLVED_OBJECT_IDS,
            DeserializationFeature.FAIL_ON_MISSING_CREATOR_PROPERTIES,
            DeserializationFeature.FAIL_ON_NULL_CREATOR_PROPERTIES,
            DeserializationFeature.FAIL_ON_TRAILING_TOKENS,
            DeserializationFeature.WRAP_EXCEPTIONS,
            DeserializationFeature.ACCEPT_SINGLE_VALUE_AS_ARRAY,
            DeserializationFeature.UNWRAP_SINGLE_VALUE_ARRAYS,
            DeserializationFeature.UNWRAP_ROOT_VALUE,
            DeserializationFeature.ACCEPT_EMPTY_STRING_AS_NULL_OBJECT,
            DeserializationFeature.ACCEPT_EMPTY_ARRAY_AS_NULL_OBJECT,
            DeserializationFeature.ACCEPT_FLOAT_AS_INT,
            DeserializationFeature.EAGER_DESERIALIZER_FETCH
        };

        DefaultTyping[] typings = new DefaultTyping[]{
            DefaultTyping.JAVA_LANG_OBJECT,
            DefaultTyping.OBJECT_AND_NON_CONCRETE,
            DefaultTyping.NON_CONCRETE_AND_ARRAYS,
            DefaultTyping.NON_FINAL,
            DefaultTyping.NON_FINAL_AND_ENUMS
        };

        ObjectMapper mapper;
        
        JsonMapper.Builder builder = JsonMapper.builder();

        // Maybe create a mapper with different typing settings
        if (data.consumeBoolean()) {
            for (int i = 0; i < typings.length; i++) {
                if (data.consumeBoolean()) {
                    builder.activateDefaultTyping(NoCheckSubTypeValidator.instance, typings[i]);
                }
            }
        }

        // Set mapper features via builder
        for (int i = 0; i < mapperfeatures.length; i++) {
            if (data.consumeBoolean()) {
                builder.enable(mapperfeatures[i]);
            } else {
                builder.disable(mapperfeatures[i]);
            }
        }

        for (int i = 0; i < serializationfeatures.length; i++) {
            if (data.consumeBoolean()) {
                builder.enable(serializationfeatures[i]);
            } else {
                builder.disable(serializationfeatures[i]);
            }
        }

        mapper = builder.build();

        int idx = data.consumeInt(0, classes.length - 1);
        r = mapper.readerFor(classes[idx]); // To initialize

        switch (data.consumeInt(0, 4)) {
        case 0:
            r = mapper.readerFor(classes[idx]);
        case 1:
            r = mapper.readerForMapOf(classes[idx]);
        case 2:
            r = mapper.readerForListOf(classes[idx]);
        case 3:
            r = mapper.readerForArrayOf(classes[idx]);
        case 4:
            fuzzInt1 = data.consumeInt(0, classes.length - 1);
            r = r.forType(mapper.constructType(classes[fuzzInt1]));
        }

        // set reader settings
        for (int i = 0; i < deserializationfeatures.length; i++) {
            if (data.consumeBoolean()) {
                r = r.with(deserializationfeatures[i]);
            } else {
                r = r.without(deserializationfeatures[i]);
            }
        }

        try {
            // Select a method and call it
            int callType = data.consumeInt();
            switch (callType%7) {
            case 0:
                // readValue
                switch (data.consumeInt(0, 14)){
                case 0:
                    r.readValue(data.consumeString(100000));
                case 1:
                    r.readValue(new MockFuzzDataInput(data.consumeString(100000)));
                case 2:
                    r.readValue(data.consumeBytes(100000));
                case 3:
                    jp = _createParser(data, mapper, r);
                    o = r.readValue(jp);
                    doThis = data.consumeBoolean();
                    if (doThis) {
                        r3 = r.withValueToUpdate(o);
                        mapper.valueToTree(o);
                    }
                case 4:
                    jp = _createParser(data, mapper, r);
                    fuzzInt1 = data.consumeInt(0, classes.length - 1);
                    mapper.readerFor(classes[fuzzInt1]).readValue(jp);
                case 5:
                    jp = _createParser(data, mapper, r);
                    fuzzInt1 = data.consumeInt(0, classes.length - 1);
                    mapper.readerFor(classes[fuzzInt1]).readValue(jp);
                case 6:
                    stringR = new StringReader(new String(data.consumeBytes(100000)));
                    r.readValue(stringR);
                case 7:
                    fileData = data.consumeRemainingAsBytes();
                    out = new FileOutputStream("fuzzFile");
                    out.write(fileData);
                    out.close();
                    r.readValue(new File("fuzzFile"));
                case 8:
                    fuzzInt1 = data.consumeInt();
                    fuzzInt2 = data.consumeInt();
                    r.readValue(data.consumeBytes(100000), fuzzInt1, fuzzInt2);
                case 9:
                    fuzzInt1 = data.consumeInt(0, classes.length - 1);
                    mapper.readValue(data.consumeBytes(100000), classes[fuzzInt1]);
                case 10:
                    fuzzInt1 = data.consumeInt(0, classes.length - 1);
                    mapper.readValue(data.consumeString(100000), classes[fuzzInt1]);
                case 11:
                    fuzzInt1 = data.consumeInt(0, classes.length - 1);
                    mapper.readValue(data.consumeBytes(1000000), data.consumeInt(), data.consumeInt(), classes[fuzzInt1]);
                case 12:
                    fuzzInt1 = data.consumeInt(0, classes.length - 1);
                    mapper.readValue(data.consumeBytes(1000000), mapper.constructType(classes[fuzzInt1]));
                case 13:
                    fuzzInt1 = data.consumeInt(0, classes.length - 1);
                    mapper.readValue(data.consumeString(1000000), mapper.constructType(classes[fuzzInt1]));
                case 14:                    
                    r.readValue(new ByteArrayInputStream(data.consumeBytes(100000)));
                }
            case 1:
                // readTree
                switch (data.consumeInt(0, 7)){
                case 0:
                    jp = _createParser(data, mapper, r);
                    o = r.readTree(jp);
                    if (data.consumeBoolean()) {
                        r3 = r.withValueToUpdate(o);
                        mapper.valueToTree(o);
                        mapper.readerForUpdating(o);
                    }
                case 1:
                    o = r.readTree(data.consumeString(100000));
                    if (data.consumeBoolean()) {
                        r3 = r.withValueToUpdate(o);
                        mapper.valueToTree(o);
                        mapper.readerForUpdating(o);
                    }
                case 2:
                    o = r.readTree(data.consumeBytes(100000));
                    if (data.consumeBoolean()) {
                        r3 = r.withValueToUpdate(o);
                        mapper.valueToTree(o);
                        mapper.readerForUpdating(o);
                    }
                case 3:
                    stringR = new StringReader(new String(data.consumeRemainingAsBytes()));
                    r.readTree(stringR);
                case 4:
                    fuzzInt1 = data.consumeInt();
                    fuzzInt2 = data.consumeInt();
                    r.readTree(data.consumeRemainingAsBytes(), fuzzInt1, fuzzInt2);
                case 5:
                    mapper.readTree(data.consumeBytes(1000000));
                case 6:
                    mapper.readTree(data.consumeString(1000000));
                case 7:
                    fuzzInt1 = data.consumeInt(0, classes.length - 1);
                    switch (data.consumeInt(0,1)) {
                    case 0:
                        mapper.readValue(data.consumeRemainingAsBytes(), classes[fuzzInt1]);
                    case 1:
                        mapper.readValue(data.consumeRemainingAsString(), classes[fuzzInt1]);
                    }
                }
            case 2:
                _readValues(data, mapper, r);                
            case 3:
                fuzzInt1 = data.consumeInt(0, classes.length - 1);
                fuzzInt2 = data.consumeInt(0, classes.length - 1);
                // addMixIn not available on immutable mapper in Jackson 3.x - skip
            case 4:
                JsonNode tree = mapper.readTree(data.consumeString(1000000));
                JsonNode node = tree.at(data.consumeString(1000000));
                doThis = data.consumeBoolean();
                if (doThis) {
                    fuzzInt1 = data.consumeInt(0, classes.length - 1);
                    mapper.treeToValue(node, classes[fuzzInt1]);
                }
                doThis = data.consumeBoolean();
                if (doThis) {
                    fuzzInt1 = data.consumeInt(0, classes.length - 1);
                    mapper.treeToValue(node, mapper.constructType(classes[fuzzInt1]));
                }
                doThis = data.consumeBoolean();
                if (doThis) {
                    r.readValue(node);
                }
                doThis = data.consumeBoolean();
                fuzzInt1 = data.consumeInt(0, classes.length - 1);
                if (doThis) {
                    mapper.treeToValue(node, classes[fuzzInt1]);
                }
            case 5:
                switch (data.consumeInt(0, 2)){
                case 0:
                    mapper.readTree(new ByteArrayInputStream(data.consumeBytes(100000)));
                case 1:
                    ObjectNode src = (ObjectNode) mapper.readTree(data.consumeString(100000));
                    TreeNode tn = src;
                    fuzzInt1 = data.consumeInt(0, classes.length - 1);
                    mapper.treeToValue(tn, classes[fuzzInt1]);
                case 2:
                    r.readTree(new MockFuzzDataInput(data.consumeString(100000)));
                }
            case 6:
                fuzzInt1 = data.consumeInt(0, classes.length - 1);
                mapper.constructType(classes[fuzzInt1]);
            }
            
            // target with();
            if (data.consumeBoolean()) {
                r2 = r.with(DeserializationFeature.ACCEPT_SINGLE_VALUE_AS_ARRAY);                
            }
        } catch (JacksonException | IOException | IllegalArgumentException | ClassCastException e) { }

        try {
            Files.delete(Paths.get("fuzzFile"));
        } catch (IOException e) { }
    }

    public static void _readValues(FuzzedDataProvider data, ObjectMapper mapper, ObjectReader r) throws IOException {
        Object o;
        ObjectReader r3;
        int fuzzInt1, fuzzInt2;
        JsonParser jp;
        byte[] fileData;
        FileOutputStream out;
        Reader stringR;
        
        // readValues
        switch (data.consumeInt(0, 8)){
        case 0:
            stringR = new StringReader(new String(data.consumeRemainingAsBytes()));
            o = r.readValues(stringR);
        case 1:
            o = r.readValues(data.consumeRemainingAsString());
        case 2:
            jp = _createParser(data, mapper, r);
            o = r.readValues(jp);
        case 3:
            fileData = data.consumeRemainingAsBytes();
            out = new FileOutputStream("fuzzFile");
            out.write(fileData);
            out.close();
            o = r.readValues(new File("fuzzFile"));
        case 4:
            fuzzInt1 = data.consumeInt();
            fuzzInt2 = data.consumeInt();
            o = r.readValues(data.consumeBytes(1000000), fuzzInt1, fuzzInt2);
        case 5:
            fuzzInt1 = data.consumeInt(0, classes.length - 1);
            jp = _createParser(data, mapper, r);
            o = mapper.readValues(jp, mapper.constructType(classes[fuzzInt1]));
        case 6:
            fuzzInt1 = data.consumeInt(0, classes.length - 1);
            jp = _createParser(data, mapper, r);
            o = mapper.readValues(jp, classes[fuzzInt1]);
        case 7:
            o = r.readValues(new MockFuzzDataInput(data.consumeString(1000000)));
        case 8:
            o = r.readValues(new ByteArrayInputStream(data.consumeBytes(100000)));
        default:
            o = r.readValues(data.consumeRemainingAsString()); // To avoid "variable o might not have been initialized"
        }
        if (data.consumeBoolean()) {
            r3 = r.withValueToUpdate(o);
            mapper.valueToTree(o);
            mapper.readerForUpdating(o);
        }
    }

    public static JsonParser _createParser(FuzzedDataProvider data, ObjectMapper mapper, ObjectReader r) throws IOException {
        int fuzzInt1, fuzzInt2;
        byte[] fileData;
        switch (data.consumeInt(0, 6)) {
        case 0:
            return r.createParser(data.consumeBytes(100000));
        case 1:
            fileData = data.consumeBytes(100000);
            FileOutputStream out = new FileOutputStream("fuzzFile");
            out.write(fileData);
            out.close();
            return r.createParser(new File("fuzzFile"));
        case 2:
            fuzzInt1 = data.consumeInt();
            fuzzInt2 = data.consumeInt();
            return r.createParser(data.consumeBytes(100000), fuzzInt1, fuzzInt2);
        case 3:
            mapper.createParser(data.consumeBytes(100000));
        case 4:
            return mapper.createParser(data.consumeString(1000000));
        case 5:            
            fuzzInt1 = data.consumeInt();
            fuzzInt2 = data.consumeInt();
            return mapper.createParser(data.consumeBytes(100000), fuzzInt1, fuzzInt2);
        case 6:
            return r.createParser(new ByteArrayInputStream(data.consumeBytes(100000)));
        }
        return r.createParser(data.consumeBytes(100000));
    }

    public static Class[] classes = { DummyClass.class, Integer.class, String.class, Byte.class, List.class, Map.class,
        TreeMap.class, BitSet.class, TimeZone.class, Date.class, Calendar.class, Locale.class, Long.class };

    public static class DummyClass {
        public TreeMap<String, Integer> _treeMap;
        public List<String> _arrayList;
        public Set<String> _hashSet;
        public Map<String, Object> _hashMap;
        public List<Integer> _asList = Arrays.asList(1, 2, 3);
        public int[] _intArray;
        public long[] _longArray;
        public short[] _shortArray;
        public float[] _floatArray;
        public double[] _doubleArray;
        public byte[] _byteArray;
        public char[] _charArray;
        public String[] _stringArray;
        public BitSet _bitSet;
        public Date _date;
        public TimeZone _timeZone;
        public Calendar _calendar;
        public Locale _locale;
        public Integer[] _integerArray;
        public boolean _boolean;
        public char _char;
        public byte _byte;
        public short _short;
        public int _int;
        public float _float;
        public Long _long;
        public Double _double;
    }


    // Test util classes
    public static final class NoCheckSubTypeValidator
        extends PolymorphicTypeValidator.Base
    {
        private static final long serialVersionUID = 1L;

        protected final static Set<String> DEFAULT_NO_DESER_CLASS_NAMES;
        static {
            Set<String> s = new HashSet<String>();        
            s.add("jaz.Zer");
            DEFAULT_NO_DESER_CLASS_NAMES = Collections.unmodifiableSet(s);
        }

        protected Set<String> _cfgIllegalClassNames = DEFAULT_NO_DESER_CLASS_NAMES;

        public static final NoCheckSubTypeValidator instance = new NoCheckSubTypeValidator(); 

        @Override
        public Validity validateBaseType(DatabindContext ctxt, JavaType baseType) {
            return Validity.INDETERMINATE;
        }

        @Override
        public Validity validateSubClassName(DatabindContext ctxt,
                JavaType baseType, String subClassName) {
            if (_cfgIllegalClassNames.contains(subClassName)) {
                return Validity.DENIED;
            }
            return Validity.ALLOWED;
        }

        @Override
        public Validity validateSubType(DatabindContext ctxt, JavaType baseType,
                JavaType subType) {
            final Class<?> raw = baseType.getRawClass();
            String full = raw.getName();
            if (_cfgIllegalClassNames.contains(full)) {
                return Validity.DENIED;
            }
            return Validity.ALLOWED;
        }
    }

    public static class MockFuzzDataInput implements DataInput
    {
        private final InputStream _input;

        public MockFuzzDataInput(byte[] data) {
            _input = new ByteArrayInputStream(data);
        }

        public MockFuzzDataInput(String utf8Data) throws IOException {
            _input = new ByteArrayInputStream(utf8Data.getBytes("UTF-8"));
        }

        public MockFuzzDataInput(InputStream in) {
            _input = in;
        }

        @Override
        public void readFully(byte[] b) throws IOException {
            throw new UnsupportedOperationException();
        }

        @Override
        public void readFully(byte[] b, int off, int len) throws IOException {
            throw new UnsupportedOperationException();
        }

        @Override
        public int skipBytes(int n) throws IOException {
            return (int) _input.skip(n);
        }

        @Override
        public boolean readBoolean() throws IOException {
            throw new UnsupportedOperationException();
        }

        @Override
        public byte readByte() throws IOException {
            int ch = _input.read();
            if (ch < 0) {
                throw new EOFException("End-of-input for readByte()");
            }
            return (byte) ch;
        }

        @Override
        public int readUnsignedByte() throws IOException {
            return readByte() & 0xFF;
        }

        @Override
        public short readShort() throws IOException {
            throw new UnsupportedOperationException();
        }

        @Override
        public int readUnsignedShort() throws IOException {
            throw new UnsupportedOperationException();
        }

        @Override
        public char readChar() throws IOException {
            throw new UnsupportedOperationException();
        }

        @Override
        public int readInt() throws IOException {
            throw new UnsupportedOperationException();
        }

        @Override
        public long readLong() throws IOException {
            throw new UnsupportedOperationException();
        }

        @Override
        public float readFloat() throws IOException {
            throw new UnsupportedOperationException();
        }

        @Override
        public double readDouble() throws IOException {
            throw new UnsupportedOperationException();
        }

        @Override
        public String readLine() throws IOException {
            throw new UnsupportedOperationException();
        }

        @Override
        public String readUTF() throws IOException {
            throw new UnsupportedOperationException();
        }
    }
}
