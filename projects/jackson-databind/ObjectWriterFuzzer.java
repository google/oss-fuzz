import com.code_intelligence.jazzer.api.FuzzedDataProvider;

import java.util.*;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.core.JsonProcessingException;

public class ObjectWriterFuzzer {
    public static void fuzzerTestOneInput(FuzzedDataProvider data) {
        ObjectMapper mapper = new ObjectMapper();

        try {
            DummyClass dc = mapper.readValue(data.consumeRemainingAsString(), DummyClass.class);
            byte[] jb = mapper.writeValueAsBytes(dc);
        } catch (JsonProcessingException e) { }
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