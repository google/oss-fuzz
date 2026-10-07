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
import com.thoughtworks.xstream.XStreamException;
import com.thoughtworks.xstream.io.StreamException;
import org.junit.platform.commons.logging.LoggerFactory;
import org.springframework.oxm.xstream.XStreamMarshaller;

import javax.xml.transform.stream.StreamResult;
import javax.xml.transform.stream.StreamSource;
import java.io.*;
import java.util.*;

public class XStreamMarshallerFuzzer {
	public static Class<?>[] classes = { DummyClass.class, Integer.class, String.class, Byte.class, List.class, Map.class,
			TreeMap.class, BitSet.class, TimeZone.class, Date.class, Calendar.class, Locale.class };

	private static final PrintStream noopStream = new PrintStream(new OutputStream() {
		@Override
		public void write(int b) {}
	});

	public static void fuzzerInitialize() {
		System.setErr(noopStream);
		System.setOut(noopStream);
	}

	public static void fuzzerTestOneInput(FuzzedDataProvider data) {
		XStreamMarshaller marshaller = new XStreamMarshaller();

		HashMap<String, Object> aliases = new HashMap<>();
		for (int i = 0; i < data.consumeInt(0, 100); i++) {
			aliases.put(data.consumeString(100), data.pickValue(classes));
		}

		if (data.consumeBoolean()) {
			marshaller.setAliases(aliases);
		}

		if (data.consumeBoolean()) {
			marshaller.supports(data.pickValue(classes));
		}

		if (data.consumeBoolean()) {
			marshaller.setEncoding(data.consumeString(100));
		}

		byte[] buffer = data.consumeBytes(1000);
		Writer writer = new StringWriter();
		Reader reader = new StringReader(writer.toString());

		// Marshal & unmarshal
		try {
			marshaller.marshal(buffer, new StreamResult(writer));
			marshaller.unmarshal(new StreamSource(reader));
		} catch (IOException | StreamException e) {}
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

		public void foo(String dummy) {}
	}
}