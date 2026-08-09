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
import com.code_intelligence.jazzer.api.FuzzerSecurityIssueMedium;

import groovy.test.*;
import junit.framework.AssertionFailedError;
import static groovy.test.GroovyAssert.shouldFail;
import java.util.Arrays;
import groovy.lang.*;

class MyObject {
	boolean a, b;

	MyObject(boolean a, boolean b) {
		this.a = a;
		this.b = b;
	}

	public boolean equals(Object anotherObject) {
		MyObject other = (MyObject) anotherObject;
		if (a != other.a) {
			return false;
		}
		if (b != other.b) {
			return false;
		}
		return true;
	}
}

class MyClosure extends Closure<MyClosure> {
	boolean shouldFail;

	MyClosure(FuzzedDataProvider data) {
		super(null);
		shouldFail = data.consumeBoolean();
	}

	public Object doCall(Object args) {
		if (shouldFail) {
			Object x = null;
			x.hashCode();
		}
		return null;
	}
}

public class TestFuzzer extends GroovyTestCase {

	public TestFuzzer(FuzzedDataProvider data) {
	}

	MyObject getObject(FuzzedDataProvider data) {
		return new MyObject(data.consumeBoolean(), data.consumeBoolean());
	}

	MyClosure getClosure(FuzzedDataProvider data) {
		return new MyClosure(data);
	}

	void printPos() {
		try {
			throw new Exception();
		} catch (Exception e) {
			e.printStackTrace(System.out);
		}
	}

	void assertLengthArrayTest(FuzzedDataProvider data) {
		var n = data.consumeInt();
		var intArray = new int[] { data.consumeInt(), data.consumeInt() };
		boolean wasEqual;
		boolean equal = (n == intArray.length);
		try {
			assertLength(n, intArray);
			wasEqual = true;
		} catch (AssertionFailedError er) {
			wasEqual = false;
		}
		if (equal != wasEqual) {
			throw new FuzzerSecurityIssueMedium("assertLength mismatch not detected");
		}
	}

	void assertLengthArrayTestTwo(FuzzedDataProvider data) {
		var length = data.consumeInt();
		var intArray = new int[data.consumeInt(1, 10)];
		boolean wasEqual;
		boolean equal = (length == intArray.length);
		try {
			assertLength(length, intArray);
			wasEqual = true;
		} catch (AssertionFailedError er) {
			wasEqual = false;
		}
		if (equal != wasEqual) {
			throw new FuzzerSecurityIssueMedium("assertLength mismatch not detected");
		}
	}

	void assertLengthCharTest(FuzzedDataProvider data) {
		var n = data.consumeInt();
		var charArray = new char[] { data.consumeChar(), data.consumeChar() };
		boolean wasEqual;
		boolean equal = (n == charArray.length);
		try {
			assertLength(n, charArray);
			wasEqual = true;
		} catch (AssertionFailedError er) {
			wasEqual = false;
		}
		if (equal != wasEqual) {
			throw new FuzzerSecurityIssueMedium("assertLength mismatch not detected");
		}
	}

	void assertLengthObjectTest(FuzzedDataProvider data) {
		var length = data.consumeInt();
		var objectArray = new MyObject[] { getObject(data), getObject(data) };
		boolean wasEqual;
		boolean equal = (length == objectArray.length);
		try {
			assertLength(length, objectArray);
			wasEqual = true;
		} catch (AssertionFailedError er) {
			wasEqual = false;
		}
		if (equal != wasEqual) {
			throw new FuzzerSecurityIssueMedium("assertObjectLength mismatch not detected");
		}
	}

	void assertEqualsStringTest(FuzzedDataProvider data) {
		var actual = data.consumeString(1000);
		var expected = data.consumeString(1000);
		boolean wasEqual;
		boolean equal = (actual.equals(expected));
		try {
			assertEquals(actual, expected);
			wasEqual = true;
		} catch (AssertionFailedError er) {
			wasEqual = false;
		}
		if (equal != wasEqual) {
			throw new FuzzerSecurityIssueMedium("assertEqual mismatch not detected");
		}
	}

	void assertEqualsObjectWithMessageTest(FuzzedDataProvider data) {
		var message = data.consumeString(100);
		var actual = getObject(data);
		var expected = getObject(data);
		boolean wasEqual;
		boolean equal = (actual.equals(expected));
		try {
			assertEquals(message, actual, expected);
			wasEqual = true;
		} catch (AssertionFailedError er) {
			wasEqual = false;
		}
		if (equal != wasEqual) {
			throw new FuzzerSecurityIssueMedium("Object mismatch not detected.");
		}
	}

	void assertEqualsObjectTest(FuzzedDataProvider data) {
		var actual = getObject(data);
		var expected = getObject(data);
		boolean wasEqual;
		boolean equal = (actual.equals(expected));
		try {
			assertEquals(actual, expected);
			wasEqual = true;
		} catch (AssertionFailedError er) {
			wasEqual = false;
		}
		if (equal != wasEqual) {
			throw new FuzzerSecurityIssueMedium("Object mismatch not detected.");
		}
	}

	void assertObjectEqualsTest(FuzzedDataProvider data) {
		var expected = getObject(data);
		var actual = getObject(data);
		boolean wasEqual;
		boolean equal = (expected.equals(actual));
		try {
			assertEquals(expected, actual);
			wasEqual = true;
		} catch (AssertionFailedError er) {
			wasEqual = false;
		}
		if (equal != wasEqual) {
			throw new FuzzerSecurityIssueMedium("assertEquals mismatch not detected");
		}
	}

	void assertObjectArrayEqualsTest(FuzzedDataProvider data) {
		var expected = new MyObject[] { getObject(data), getObject(data) };
		var actual = new MyObject[] { getObject(data), getObject(data) };
		boolean wasEqual;
		boolean equal = (Arrays.equals(expected, actual));
		try {
			assertArrayEquals(expected, actual);
			wasEqual = true;
		} catch (AssertionFailedError er) {
			wasEqual = false;
		}
		if (equal != wasEqual) {
			throw new FuzzerSecurityIssueMedium("assertObjectArrayEquals mismatch not detected");
		}
	}

	void assertInspectTest(FuzzedDataProvider data) {
		var value = getObject(data);
		var expected = data.consumeString(100);
		boolean wasEqual;
		boolean equal = (value.toString() == expected);
		try {
			assertInspect(value, expected);
			wasEqual = true;
		} catch (AssertionFailedError er) {
			wasEqual = false;
		}
		if (equal != wasEqual) {
			throw new FuzzerSecurityIssueMedium("assertInspect mismatch not detected");
		}
	}

	void shouldFailTest(FuzzedDataProvider data) {
		MyClosure c = new MyClosure(data);
		boolean hasFailed;
		try {
			shouldFail(c);
			hasFailed = true;
		} catch (AssertionError er) {
			hasFailed = false;
		}
		if (c.shouldFail != hasFailed) {
			throw new FuzzerSecurityIssueMedium("failure not detected");
		}
	}

	void shouldFailClassCLosureTest(FuzzedDataProvider data) {
		MyClosure c = new MyClosure(data);
		boolean hasFailed;
		try {
			shouldFail(NullPointerException.class, c);
			hasFailed = true;
		} catch (AssertionError er) {
			hasFailed = false;
		}
		if (c.shouldFail != hasFailed) {
			throw new FuzzerSecurityIssueMedium("failure not detected");
		}
	}

	void shouldFailWithCauseTest(FuzzedDataProvider data) {
		MyClosure c = new MyClosure(data);
		boolean hasFailed;
		try {
			shouldFailWithCause(NullPointerException.class, c);
			hasFailed = true;
		} catch (AssertionError er) {
			hasFailed = false;
		}
		if (c.shouldFail != hasFailed) {
			throw new FuzzerSecurityIssueMedium("failure not detected");
		}
	}

	void shouldFailStringTest(FuzzedDataProvider data) {
		try {
			shouldFail(data.consumeString(1000));
		} catch (AssertionError er) {
		}
	}

	void assertToStringTest(FuzzedDataProvider data) {
		var value = getObject(data);
		var expected = data.consumeString(100);
		boolean wasEqual;
		boolean equal = (value.toString() == expected);
		try {
			assertToString(value, expected);
			wasEqual = true;
		} catch (AssertionFailedError er) {
			wasEqual = false;
		}
		if (equal != wasEqual) {
			throw new FuzzerSecurityIssueMedium("assertToString mismatch not detected");
		}
	}

	void runFuzzerTest(FuzzedDataProvider data) {
		assertObjectArrayEqualsTest(data);
		assertObjectEqualsTest(data);

		try {
			assertContains(data.consumeChar(), new char[] { data.consumeChar(), data.consumeChar() });
		} catch (AssertionFailedError er) {
			/* documented ignore */
		}

		try {
			assertContains(data.consumeInt(), new int[] { data.consumeInt(), data.consumeInt() });
		} catch (AssertionFailedError er) {
			/* documented ignore */
		}

		assertEqualsObjectWithMessageTest(data);
		assertEqualsObjectTest(data);
		assertEqualsStringTest(data);
		assertInspectTest(data);
		assertLengthCharTest(data);
		assertLengthArrayTest(data);
		assertLengthArrayTestTwo(data);
		assertLengthObjectTest(data);
		assertToStringTest(data);

		try {
			fixEOLs(data.consumeString(1000));
		} catch (AssertionFailedError er) {
			/* documented ignore */
		}

		try {
			getMethodName();
		} catch (AssertionFailedError er) {
			/* documented ignore */
		}

		try {
			getName();
		} catch (AssertionFailedError er) {
			/* documented ignore */
		}

		try {
			getTestClassName();
		} catch (AssertionFailedError er) {
			/* documented ignore */
		}

		try {
			notYetImplemented(getObject(data));
		} catch (Exception er) {
			/* documented ignore */
		}

		try {
			assertScript(data.consumeString(1000));
		} catch (Exception er) {
			/* documented ignore */
		}

		try {
			notYetImplemented();
		} catch (AssertionError er) {
			/* documented ignore */
		}

		shouldFailTest(data);
		shouldFailStringTest(data);

		try {
			shouldFail(NullPointerException.class, data.consumeString(100));
		} catch (AssertionError er) {
			/* documented ignore */
		}

		shouldFailClassCLosureTest(data);
		shouldFailWithCauseTest(data);
	}

	public static void fuzzerTestOneInput(FuzzedDataProvider data) {
		TestFuzzer testClosure = new TestFuzzer(data);
		testClosure.runFuzzerTest(data);
	}
}
