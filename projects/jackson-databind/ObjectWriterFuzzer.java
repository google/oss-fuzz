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

import tools.jackson.databind.ObjectMapper;
import tools.jackson.databind.MapperFeature;
import tools.jackson.databind.SerializationFeature;
import tools.jackson.databind.json.JsonMapper;
import tools.jackson.core.JacksonException;

public class ObjectWriterFuzzer {
    public static void fuzzerTestOneInput(FuzzedDataProvider data) {

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
            SerializationFeature.FAIL_ON_UNWRAPPED_TYPE_IDENTIFIERS,
            SerializationFeature.WRITE_SELF_REFERENCES_AS_NULL,
            SerializationFeature.CLOSE_CLOSEABLE,
            SerializationFeature.FLUSH_AFTER_WRITE_VALUE,
            SerializationFeature.WRITE_CHAR_ARRAYS_AS_JSON_ARRAYS,
            SerializationFeature.WRITE_EMPTY_JSON_ARRAYS,
            SerializationFeature.WRITE_SINGLE_ELEM_ARRAYS_UNWRAPPED,
            SerializationFeature.ORDER_MAP_ENTRIES_BY_KEYS,
            SerializationFeature.EAGER_SERIALIZER_FETCH,
            SerializationFeature.USE_EQUALITY_FOR_OBJECT_ID
        };

        // Build mapper with features via builder (Jackson 3.x style)
        JsonMapper.Builder builder = JsonMapper.builder();
        
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

        ObjectMapper mapper = builder.build();

        try {
            DummyClass dc = mapper.readValue(data.consumeRemainingAsString(), DummyClass.class);
            byte[] jb = mapper.writeValueAsBytes(dc);
        } catch (JacksonException e) { }
    }

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
}
