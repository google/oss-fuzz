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


package io.netty.buffer;

import java.nio.charset.Charset;
import java.nio.CharBuffer;

import com.code_intelligence.jazzer.api.FuzzedDataProvider;

public class ByteBufUtilFuzzer {
	
	private FuzzedDataProvider fuzzedDataProvider;
	
	public ByteBufUtilFuzzer(FuzzedDataProvider fuzzedDataProvider) {
		this.fuzzedDataProvider = fuzzedDataProvider;
	}

	byte[] getByteArray() {
		int length = fuzzedDataProvider.consumeInt(0, fuzzedDataProvider.remainingBytes());
		return fuzzedDataProvider.consumeBytes(length);
	}

	CharBuffer getCharBuffer() {
		CharSequence charSequence = getCharSequence();
		CharBuffer charBuffer = CharBuffer.allocate(charSequence.length());
		charBuffer.put(charSequence.toString());
		return charBuffer;
	}

	CharSequence getCharSequence() {
		int length = fuzzedDataProvider.consumeInt(0, fuzzedDataProvider.remainingBytes());
		return fuzzedDataProvider.consumeString(length);
	}

	int validIndex(ByteBuf buffer) {
		int max = buffer.capacity();
		if (max != 0) {
			max -= 1; // zero index is first element
		}
		return fuzzedDataProvider.consumeInt(0, max);
	}

	int validLength(ByteBuf buffer, int start) {
		int length = validIndex(buffer);
		if (start + length > buffer.capacity()) {
			length = buffer.capacity() - start;
			length -= 1; // zero index is first element
		}
		return length;
	}

	void test() {
		try {
			int fromIndex = fuzzedDataProvider.consumeInt();
			int toIndex = fuzzedDataProvider.consumeInt();
			byte value = fuzzedDataProvider.consumeByte();
			ByteBuf buffer = Unpooled.copiedBuffer(getByteArray());
			ByteBuf secondBuffer = Unpooled.copiedBuffer(getByteArray());
			if (buffer.capacity() != 0) {
				// fromIndex and toIndex need to be valid indices, or indexOf
				// will throw an out of bounds exception, which is not
				// documented
				ByteBufUtil.indexOf(buffer, Math.abs(fromIndex % buffer.capacity()), Math.abs(toIndex % buffer.capacity()), value);
			}
			ByteBufUtil.indexOf(secondBuffer, buffer);
			ByteBufUtil.hexDump(buffer);
			ByteBufUtil.hashCode(buffer);

			CharSequence charSequence = getCharSequence();
			if (buffer.capacity() >= buffer.writerIndex() + charSequence.length()) {
				ByteBufUtil.writeUtf8(buffer, charSequence);
			}
			ByteBufUtil.writeUtf8(buffer.alloc(), charSequence);
			ByteBufUtil.encodeString(buffer.alloc(), getCharBuffer(), Charset.forName("UTF-8"));
			if(buffer.capacity() != 0) {
				// again, out of bounds exceptions if the input array is empty
				int index = validIndex(buffer);
				int length = validLength(buffer, index);
				ByteBufUtil.decodeString(buffer, index, length, Charset.forName("US-ASCII"));
				CompositeByteBuf compositeByteBuf = Unpooled.compositeBuffer().addComponent(buffer);
				ByteBufUtil.firstIndexOf(compositeByteBuf, index, length, value);
			}

			ByteBufUtil.equals(buffer, secondBuffer);
			ByteBufUtil.compare(buffer, secondBuffer);
			ByteBufUtil.appendPrettyHexDump(new StringBuilder(charSequence), secondBuffer);
			int index = validIndex(buffer);
			int length = validLength(buffer, index);
			ByteBufUtil.isText(buffer, Charset.forName("UTF-8"));
			ByteBufUtil.isText(buffer,index, length, Charset.forName("UTF-8"));
			ByteBufUtil.prettyHexDump(buffer);
			ByteBufUtil.swapInt(fuzzedDataProvider.consumeInt());
			ByteBufUtil.swapLong(fuzzedDataProvider.consumeLong());
			ByteBufUtil.swapMedium(fuzzedDataProvider.consumeInt());
			ByteBufUtil.swapShort(fuzzedDataProvider.consumeShort());
		} catch (IllegalArgumentException e) {

		} catch (IllegalStateException e) {

		}
	}

	public static void fuzzerTestOneInput(FuzzedDataProvider fuzzedDataProvider) {
		ByteBufUtilFuzzer fixture = new ByteBufUtilFuzzer(fuzzedDataProvider);
		fixture.test();
	}
}