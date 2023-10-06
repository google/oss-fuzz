package ossfuzz;

import com.code_intelligence.jazzer.api.*;

import org.glassfish.jaxb.runtime.*;

import java.math.BigDecimal;
import java.math.BigInteger;
import java.util.*;

public class DataTypeConverterFuzzer {

	String m_string;
	int m_int;

	DataTypeConverterFuzzer(int integer, String string) {
		m_int = integer;
		m_string = string;

	}

	void test() {

		DatatypeConverterImpl.theInstance.printHexBinary(m_string.getBytes());

		Calendar calendar = null;
		try {
			calendar = DatatypeConverterImpl.theInstance.parseTime(m_string);
			DatatypeConverterImpl.theInstance.printTime(calendar);
		} catch (IllegalArgumentException e) {
			/* documented, ignore */
		}

		try {
			String base64 = DatatypeConverterImpl.theInstance.printBase64Binary(m_string.getBytes());
			DatatypeConverterImpl.theInstance.parseBase64Binary(base64);
		} catch (IllegalArgumentException e) {
			/* documented, ignore */
		}

		try {
			String type = DatatypeConverterImpl.theInstance.parseAnySimpleType(m_string);
			DatatypeConverterImpl.theInstance.printAnySimpleType(type);
		} catch (IllegalArgumentException e) {
			/* documented, ignore */
		}

		try {
			boolean bool = DatatypeConverterImpl.theInstance.parseBoolean(m_string);
			DatatypeConverterImpl.theInstance.printBoolean(bool);
		} catch (IllegalArgumentException e) {
			/* documented, ignore */
		}

		try {
			BigDecimal bigDecimal = DatatypeConverterImpl.theInstance.parseDecimal(m_string);
			DatatypeConverterImpl.theInstance.printDecimal(bigDecimal);
		} catch (NumberFormatException e) {
			/* documented, ignore */
		} catch (IllegalArgumentException e) {

		}

		try {
			byte m_byte = DatatypeConverterImpl.theInstance.parseByte(m_string);
			DatatypeConverterImpl.theInstance.printByte(m_byte);
		} catch (IllegalArgumentException e) {
			/* documented, ignore */
		}

		try {
			double dbl = DatatypeConverterImpl.theInstance.parseDouble(m_string);
			DatatypeConverterImpl.theInstance.printDouble(dbl);
		} catch (NumberFormatException e) {
			/* documented, ignore */
		}

		try {
			Calendar dateTime = DatatypeConverterImpl.theInstance.parseDateTime(m_string);
			DatatypeConverterImpl.theInstance.printDateTime(dateTime);
		} catch (IllegalArgumentException e) {
			/* documented, ignore */
		}

		try {
			long longV = DatatypeConverterImpl.theInstance.parseUnsignedInt(m_string);
			DatatypeConverterImpl.theInstance.printUnsignedInt(longV);
		} catch (NumberFormatException e) {
			/* documented, ignore */
		}

		try {
			int shrt = DatatypeConverterImpl.theInstance.parseUnsignedShort(m_string);
			DatatypeConverterImpl.theInstance.printUnsignedShort(shrt);
		} catch (NumberFormatException e) {
			/* documented, ignore */
		}

		try {
			Calendar time = DatatypeConverterImpl.theInstance.parseTime(m_string);
			DatatypeConverterImpl.theInstance.printTime(time);
		} catch (IllegalArgumentException e) {
			/* documented, ignore */
		}

		try {
			Calendar date = DatatypeConverterImpl.theInstance.parseDate(m_string);
			DatatypeConverterImpl.theInstance.printDate(date);
		} catch (IllegalArgumentException e) {
			/* documented, ignore */
		}

		try {
			String smplType = DatatypeConverterImpl.theInstance.parseAnySimpleType(m_string);
			DatatypeConverterImpl.theInstance.printAnySimpleType(smplType);
		} catch (IllegalArgumentException e) {
			/* documented, ignore */
		}

		try {
			String strg = DatatypeConverterImpl.theInstance.parseString(m_string);
			DatatypeConverterImpl.theInstance.printString(strg);
		} catch (IllegalArgumentException e) {
			/* documented, ignore */
		}

		try {
			BigInteger bigInteger = DatatypeConverterImpl.theInstance.parseInteger(m_string);
			DatatypeConverterImpl.theInstance.printInteger(bigInteger);
		} catch (IllegalArgumentException e) {
			/* documented, ignore */
		}

		try {
			int intgr = DatatypeConverterImpl.theInstance.parseInt(m_string);
			DatatypeConverterImpl.theInstance.printInt(intgr);
		} catch (IllegalArgumentException e) {
			/* documented, ignore */
		}

		try {
			long lng = DatatypeConverterImpl.theInstance.parseLong(m_string);
			DatatypeConverterImpl.theInstance.printLong(lng);
		} catch (IllegalArgumentException e) {
			/* documented, ignore */
		}

		try {
			short shrt = DatatypeConverterImpl.theInstance.parseShort(m_string);
			DatatypeConverterImpl.theInstance.printShort(shrt);
		} catch (IllegalArgumentException e) {
			/* documented, ignore */
		}

		try {
			float flt = DatatypeConverterImpl.theInstance.parseFloat(m_string);
			DatatypeConverterImpl.theInstance.printFloat(flt);
		} catch (IllegalArgumentException e) {
			/* documented, ignore */
		}

	}

	public static void fuzzerTestOneInput(FuzzedDataProvider fuzzedDataProvider) {
		DataTypeConverterFuzzer testClosure = new DataTypeConverterFuzzer(
				fuzzedDataProvider.consumeInt(),
				fuzzedDataProvider.consumeRemainingAsString());

		testClosure.test();
	}
}