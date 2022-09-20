package ossfuzz;

import java.io.ByteArrayInputStream;
import java.io.IOException;

import com.code_intelligence.jazzer.api.FuzzedDataProvider;

import org.apache.bcel.classfile.*;

public class BcelFuzzer {

	BcelFuzzer(FuzzedDataProvider fuzzedDataProvider) {

	}

	void test(FuzzedDataProvider fuzzedDataProvider) throws Exception {
		var m_string = fuzzedDataProvider.consumeString(10);
		var m_byte = fuzzedDataProvider.consumeRemainingAsBytes();
		try {
			new ClassParser(new ByteArrayInputStream(m_byte), m_string).parse();
		} catch (IOException e) {
			// documented ignore
		} catch (ClassFormatException e) {
			// documented ignore
		}
	}

	public static void fuzzerTestOneInput(FuzzedDataProvider fuzzedDataProvider) throws Exception {
		BcelFuzzer testClosure = new BcelFuzzer(fuzzedDataProvider);

		testClosure.test(fuzzedDataProvider);
	}
}