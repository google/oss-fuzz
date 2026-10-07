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
////////////////////////////////////////////////////////////////////////////////
import com.code_intelligence.jazzer.api.FuzzedDataProvider;
import com.code_intelligence.jazzer.api.FuzzerSecurityIssueLow;
import com.google.common.hash.HashCode;
import com.google.common.hash.Hasher;
import com.google.common.hash.HashFunction;
import com.google.common.hash.Hashing;
import java.lang.IllegalStateException;

public class HashingFuzzer {

	public static class HashInputData {

		public HashInputData(FuzzedDataProvider fuzzedDataProvider) {
			m_bool = fuzzedDataProvider.consumeBoolean();
			m_bytes = fuzzedDataProvider.consumeBytes(2);
			m_char = fuzzedDataProvider.consumeChar();
			m_double = fuzzedDataProvider.consumeDouble();
			m_float = fuzzedDataProvider.consumeFloat();
			m_int = fuzzedDataProvider.consumeInt();
			m_long = fuzzedDataProvider.consumeLong();
			m_short = fuzzedDataProvider.consumeShort();
			m_string = fuzzedDataProvider.consumeRemainingAsString();
		}

		public boolean getBoolean() {
			return m_bool;
		}

		public byte getByte() {
			return (m_bytes.length > 0) ? m_bytes[0] : (byte)m_int;
		}

		public byte[] getBytes() {
			return m_bytes;
		}

		public char getChar() {
			return m_char;
		}

		public double getDouble() {
			return m_double;
		}

		public float getFloat() {
			return m_float;
		}

		public int getInt() {
			return m_int;
		}

		public long getLong() {
			return m_long;
		}

		public short getShort() {
			return m_short;
		}

		public String getString() {
			return m_string;
		}

		private boolean m_bool;
		private byte m_bytes[];
		private char m_char;
		private double m_double;
		private float m_float;
		private int m_int;
		private long m_long;
		private short m_short;
		private String m_string;
	}

	private static void testHashCode(HashCode hc) {
		try {
			hc.bits();

			try {
				int i = hc.asInt();
				HashCode.fromInt(i);
			} catch (IllegalStateException ise) {
				/* documented, ignore */
			}

			try {
				long l = hc.asLong();
				HashCode.fromLong(l);
			} catch (IllegalStateException ise) {
				/* documented, ignore */
			}

			hc.padToLong();
			byte[] bytes = hc.asBytes();
			hc.writeBytesTo(bytes,0,bytes.length);
			HashCode.fromBytes(bytes);

			String s = hc.toString();
			HashCode.fromString(s);

			hc.hashCode();
		} catch (IllegalArgumentException e) {
			/* ignore */
		} catch (Exception e) {
			throw new FuzzerSecurityIssueLow("Undocumented Exception");
		}
	}

	private static void testHash(HashFunction hash, HashInputData hashInputData) {
		HashCode hc = null;
		try {
			Hasher h = hash.newHasher();
			h.putBoolean(hashInputData.getBoolean());
			h.putByte(hashInputData.getByte());
			h.putBytes(hashInputData.getBytes());
			h.putChar(hashInputData.getChar());
			h.putDouble(hashInputData.getDouble());
			h.putFloat(hashInputData.getFloat());
			h.putInt(hashInputData.getInt());
			h.putLong(hashInputData.getLong());
			h.putShort(hashInputData.getShort());
			h.putUnencodedChars(hashInputData.getString());
			hc = h.hash();
		} catch (IllegalArgumentException e) {
			/* ignore */
		} catch (Exception e) {
			throw new FuzzerSecurityIssueLow("Undocumented Exception");
		}

		if (hc != null) {
			testHashCode(hc);
		}

		/*
		 * fromString documents it accepts only well-formated input,
		 * but doesn't document what it does when ill-formated input
		 * is provided. Feed it some fuzz data and find out.
		 */
		try {
			HashCode.fromString(hashInputData.getString());
		} catch (IllegalArgumentException e) {
			/* ignore */
		} catch(Exception e) {
			e.printStackTrace(System.out);
			throw new FuzzerSecurityIssueLow("Undocumented Exception");
		}
	}

	public static void fuzzerTestOneInput(FuzzedDataProvider fuzzedDataProvider) {
		// Choose realistic and valid minimumBits value; this is normally not controlled by the user
		int minimumBits = fuzzedDataProvider.consumeInt(1, 8192);
		int seed = fuzzedDataProvider.consumeInt();
		int k0 = fuzzedDataProvider.consumeInt();
		int k1 = fuzzedDataProvider.consumeInt();

		HashInputData hashInputData = new HashInputData(fuzzedDataProvider);

		/*
		 * testHash handles exceptions itself, so this try-block
		 * only catches exceptions thrown by Hashing's "factory"
		 * functions, none of which is documented to throw
		 * exceptions.
		 */
		try {
			testHash(Hashing.adler32(), hashInputData);
			testHash(Hashing.crc32(), hashInputData);
			testHash(Hashing.crc32c(), hashInputData);
			testHash(Hashing.farmHashFingerprint64(), hashInputData);
			testHash(Hashing.goodFastHash(minimumBits), hashInputData);
			testHash(Hashing.murmur3_128(), hashInputData);
			testHash(Hashing.murmur3_128(seed), hashInputData);
			testHash(Hashing.murmur3_32(), hashInputData);
			testHash(Hashing.murmur3_32(seed), hashInputData);
			testHash(Hashing.md5(), hashInputData);
			testHash(Hashing.sha1(), hashInputData);
			testHash(Hashing.sha256(), hashInputData);
			testHash(Hashing.sha384(), hashInputData);
			testHash(Hashing.sha512(), hashInputData);
			testHash(Hashing.sipHash24(), hashInputData);
			testHash(Hashing.sipHash24(k0, k1), hashInputData);
		} catch (IllegalArgumentException e) {
			/* ignore */
		} catch (Exception e) {
			e.printStackTrace(System.out);
			throw new FuzzerSecurityIssueLow("Undocumented Exception");
		}
	}
}
