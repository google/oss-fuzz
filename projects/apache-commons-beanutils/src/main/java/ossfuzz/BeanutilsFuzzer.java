/*
 * Copyright 2022 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
 
package ossfuzz;

import java.util.HashMap;
import java.util.Map;

import org.apache.commons.beanutils2.BasicDynaClass;
import org.apache.commons.beanutils2.DynaBean;
import org.apache.commons.beanutils2.DynaClass;
import org.apache.commons.beanutils2.DynaProperty;

import com.code_intelligence.jazzer.api.FuzzedDataProvider;
import com.code_intelligence.jazzer.api.FuzzerSecurityIssueLow;

public class BeanutilsFuzzer {

	String m_string;
	int m_int;
	int m_int_array[];
	String m_string_array[];
	boolean m_bool;
	double m_double;
	float m_float;
	short m_short;
	long m_long;
	Map<String, Object> m_map;

	BeanutilsFuzzer(int integer, String string, int[] intArray, boolean bool, double dbl, float flt,
			Map<String, Object> map,
			String string_array[], short shrt, long lng) {
		m_int = integer;
		m_string = string;
		m_bool = bool;
		m_int_array = intArray;
		m_double = dbl;
		m_float = flt;
		m_map = map;
		m_string_array = string_array;
		m_short = shrt;
		m_long = lng;
	}

	BeanutilsFuzzer(FuzzedDataProvider fuzzedDataProvider) {

		m_int = fuzzedDataProvider.consumeInt();
		m_int_array = fuzzedIntArray(fuzzedDataProvider);
		m_bool = fuzzedDataProvider.consumeBoolean();
		m_double = fuzzedDataProvider.consumeDouble();
		m_float = fuzzedDataProvider.consumeFloat();
		m_map = fuzzedMap(fuzzedDataProvider);
		m_string_array = fuzzedStringArray(fuzzedDataProvider);
		m_short = fuzzedDataProvider.consumeShort();
		m_long = fuzzedDataProvider.consumeLong();

		m_string = fuzzedDataProvider.consumeRemainingAsAsciiString();
	}

	protected DynaClass createDynaClass() {

		final int[] intArray = new int[0];
		final String[] stringArray = new String[0];

		final DynaClass dynaClass = new BasicDynaClass("TestDynaClass", null,
				new DynaProperty[] {
						new DynaProperty("booleanProperty", Boolean.TYPE),
						new DynaProperty("booleanSecond", Boolean.TYPE),
						new DynaProperty("doubleProperty", Double.TYPE),
						new DynaProperty("floatProperty", Float.TYPE),
						new DynaProperty("intArray", intArray.getClass()),
						new DynaProperty("intProperty", Integer.TYPE),
						new DynaProperty("longProperty", Long.TYPE),
						new DynaProperty("mappedProperty", Map.class),
						new DynaProperty("shortProperty", Short.TYPE),
						new DynaProperty("stringArray", stringArray.getClass()),
						new DynaProperty("stringProperty", String.class),
				});
		return dynaClass;

	}

	int[] fuzzedIntArray(FuzzedDataProvider fuzzedDataProvider) {
		int n = fuzzedDataProvider.consumeInt(1, 100);
		int array[] = new int[n];
		for (int i = 0; i < n; ++i) {
			array[i] = fuzzedDataProvider.consumeInt();
		}
		return array;
	}

	String[] fuzzedStringArray(FuzzedDataProvider fuzzedDataProvider) {
		int n = fuzzedDataProvider.consumeInt(1, 100);
		String array[] = new String[n];
		for (int i = 0; i < n; ++i) {
			array[i] = fuzzedDataProvider.consumeString(16);
		}
		return array;
	}

	Map<String, Object> fuzzedMap(FuzzedDataProvider fuzzedDataProvider) {
		int n = fuzzedDataProvider.consumeInt(1, 100);
		Map<String, Object> map = new HashMap<String, Object>();

		for (int i = 0; i < n; i++) {
			switch (fuzzedDataProvider.consumeInt(0, 7)) {
				case 0:
					map.put(fuzzedDataProvider.consumeString(16), new Integer(fuzzedDataProvider.consumeInt()));
					break;
				case 1:
					map.put(fuzzedDataProvider.consumeString(16), new Float(fuzzedDataProvider.consumeFloat()));
					break;
				case 2:
					map.put(fuzzedDataProvider.consumeString(16), new Double(fuzzedDataProvider.consumeDouble()));
					break;
				case 3:
					map.put(fuzzedDataProvider.consumeString(16), new String(fuzzedDataProvider.consumeString(16)));
					break;
				case 4:
					map.put(fuzzedDataProvider.consumeString(16), new Boolean(fuzzedDataProvider.consumeBoolean()));
					break;
				case 5:
					map.put(fuzzedDataProvider.consumeString(16), fuzzedIntArray(fuzzedDataProvider));
					break;
				case 6:
					map.put(fuzzedDataProvider.consumeString(16), fuzzedMap(fuzzedDataProvider));
					break;
			}

		}

		return map;
	}

	void test() throws Exception {

		final DynaClass dynaClass = createDynaClass();
		DynaBean bean = dynaClass.newInstance();

		bean.set("booleanProperty", new Boolean(m_bool));
		bean.set("booleanSecond", new Boolean(m_bool));

		if (!bean.get("booleanSecond").equals(new Boolean(m_bool))) {
			throw new FuzzerSecurityIssueLow("Data corruption detected");
		}

		bean.set("doubleProperty", new Double(m_double));
		if (!bean.get("doubleProperty").equals(new Double(m_double))) {
			throw new FuzzerSecurityIssueLow("Data corruption detected");
		}

		bean.set("floatProperty", new Float(m_float));
		if (!bean.get("floatProperty").equals(new Float(m_float))) {
			throw new FuzzerSecurityIssueLow("Data corruption detected");
		}

		bean.set("intArray", m_int_array);
		if (!bean.get("intArray").equals(m_int_array)) {
			throw new FuzzerSecurityIssueLow("Data corruption detected");
		}

		bean.set("stringArray", m_string_array);
		if (!bean.get("stringArray").equals(m_string_array)) {
			throw new FuzzerSecurityIssueLow("Data corruption detected");
		}

		bean.set("mappedProperty", m_map);
		if (!bean.get("mappedProperty").equals(m_map)) {
			throw new FuzzerSecurityIssueLow("Data corruption detected");
		}

		bean.set("intProperty", new Integer(m_int));
		if (!bean.get("intProperty").equals(new Integer(m_int))) {
			throw new FuzzerSecurityIssueLow("Data corruption detected");
		}

		bean.set("longProperty", new Long(m_long));
		if (!bean.get("longProperty").equals(new Long(m_long))) {
			throw new FuzzerSecurityIssueLow("Data corruption detected");
		}

		bean.set("shortProperty", new Short(m_short));
		if (!bean.get("shortProperty").equals(new Short(m_short))) {
			throw new FuzzerSecurityIssueLow("Data corruption detected");
		}
	}

	public static void fuzzerTestOneInput(FuzzedDataProvider fuzzedDataProvider) throws Exception {
		BeanutilsFuzzer testClosure = new BeanutilsFuzzer(fuzzedDataProvider);

		testClosure.test();
	}
}