"use strict";
/*
 * Copyright 2023 Code Intelligence GmbH
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
Object.defineProperty(exports, "__esModule", { value: true });
exports.FuzzedDataProvider = exports.FloatLengthError = void 0;
/**
 * Error class for functions that accept a length value which is thrown if that length is not a whole number to ensure
 * the fuzzed data buffer is only ever indexed by whole numbers.
 */
class FloatLengthError extends Error {
    constructor() {
        super();
        this.name = "FLOAT_LENGTH_ERROR";
        this.message = "length value must be an integer";
    }
}
exports.FloatLengthError = FloatLengthError;
/**
 * Helper class for reading primitive types from the bytes of the raw fuzzer input.
 * Arrays are read from the beginning of the data buffer, whereas individual elements are read
 * from the end of the data buffer.
 * This implementation is based on the FuzzedDataProvider.h from the libFuzzer library
 * https://github.com/llvm-mirror/compiler-rt/blob/master/include/fuzzer/FuzzedDataProvider.h
 */
class FuzzedDataProvider {
    data;
    dataPtr = -1;
    /** The number of remaining bytes that can be consumed from the fuzzer input data. */
    _remainingBytes = 0;
    /**
     * A lookup table that maps input values to output characters in a cyclical manner.
     * The output characters are evenly distributed across the range of printable ASCII characters (32-126)
     */
    lookupTable = new Uint8Array(256);
    static min_float = -3.4028235e38;
    static max_float = 3.4028235e38;
    static min_double = -Number.MAX_VALUE;
    static max_double = Number.MAX_VALUE;
    /**
     * @param data - a buffer containing the fuzzer input
     */
    constructor(data) {
        this.data = data;
        if (data.length > 0) {
            this.dataPtr = 0;
            this._remainingBytes = data.length;
        }
        /**
         * Populate the lookup table with a mapping of input values to output characters
         */
        let nextChar = 32;
        for (let i = 0; i < 256; i++) {
            this.lookupTable[i] = nextChar;
            nextChar++;
            if (nextChar > 126) {
                nextChar = 32;
            }
        }
    }
    /**
     * @returns the number of remaining bytes in the fuzzer input.
     */
    get remainingBytes() {
        return this._remainingBytes;
    }
    /**
     * -----------------------------------------------------
     * Functions for reading data from the back of fuzzer input in
     * little-endian order.
     * -----------------------------------------------------
     */
    /**
     * Consumes a byte from fuzzer input and converts it into boolean.
     * @returns a `boolean` - if LSB is 0, returns `false`, otherwise `true`
     */
    consumeBoolean() {
        return (this.consumeIntegral(1) & 1) == 1;
    }
    /**
     * Consumes an Integral number from the fuzzer input.
     * @param maxNumBytes - the maximum number of bytes to consume from the fuzzer input data
     * @param isSigned - whether the number is signed
     * @returns an integral
     */
    consumeIntegral(maxNumBytes, isSigned = false) {
        if (!Number.isInteger(maxNumBytes)) {
            throw new FloatLengthError();
        }
        return this.consumeIntegralLEorBE(maxNumBytes, isSigned, true);
    }
    /**
     * Consumes several bytes from fuzzer data and converts them to a number that is
     * in the range of [min, max]. The number of bytes consumed is determined by
     * the size of the range. If there is no more fuzzer data available, the returned
     * number will be `min`.
     * @param min lower bound of the range (inclusive)
     * @param max upper bound of the range (inclusive)
     * @returns a number in the provided range
     */
    consumeIntegralInRange(min, max) {
        return this.consumeIntegralInRangeLEorBE(min, max, true);
    }
    /**
     * Consumes a big integral from the fuzzer input.
     * @param maxNumBytesToConsume - the maximum number of bytes to consume from the fuzzer input data
     * @param isSigned - whether the number is signed
     * @returns a big integral
     */
    consumeBigIntegral(maxNumBytesToConsume, isSigned = false) {
        if (!Number.isInteger(maxNumBytesToConsume)) {
            throw new FloatLengthError();
        }
        return this.consumeBigIntegralLEorBE(maxNumBytesToConsume, isSigned, true);
    }
    /**
     * Consumes several bytes from fuzzer data and converts them to a bigint that is
     * in the range of [min, max]. The number of bytes consumed is determined by
     * the size of the range. If there is no more fuzzer data available, the returned
     * number will be `min`.
     * @param min lower bound of the range (inclusive)
     * @param max upper bound of the range (inclusive)
     * @returns a number in the provided range
     */
    consumeBigIntegralInRange(min, max) {
        return this.consumeBigIntegralInRangeLEorBE(min, max, true);
    }
    /**
     * Consumes am IEEE 754 floating-point number from the fuzzer input.
     * The number is read as is, without any conversion.
     * @returns a `number` that may have a special value (e.g. a NaN or infinity)
     */
    consumeNumber() {
        if (this._remainingBytes == 0)
            return 0;
        if (this._remainingBytes < 8) {
            // not enough data: copy to a larger buffer
            const copiedData = Buffer.alloc(8);
            this.data.copy(copiedData, 8 - this._remainingBytes, this.dataPtr, this.dataPtr + this._remainingBytes);
            this._remainingBytes = 0;
            return copiedData.readDoubleLE();
        }
        this._remainingBytes -= 8;
        return this.data.readDoubleLE(this.dataPtr + this._remainingBytes);
    }
    /**
     * Consumes at most 9 bytes from fuzzer input and converts them to an
     * IEEE-754 number in the range [min, max].
     * @param min - lower bound of the range (inclusive)
     * @param max - upper bound of the range (inclusive)
     * @returns a `number` in the provided range
     */
    consumeNumberInRange(min, max) {
        return this.consumeDoubleInRange(min, max);
    }
    /**
     * Consumes a 32-bit `float` from the fuzzer input.
     * @returns a `float` that may have a special value (e.g. a NaN or infinity)
     */
    consumeFloat() {
        return this.consumeFloatInRange(FuzzedDataProvider.min_float, FuzzedDataProvider.max_float);
    }
    /**
     * Consumes a 32-bit `float` from fuzzer input and converts it to an
     * IEEE-754 number in the range [min, max].
     * @param min - lower bound of the range (inclusive)
     * @param max - upper bound of the range (inclusive)
     * @returns a `float` in the provided range
     */
    consumeFloatInRange(min, max) {
        if (min == max)
            return min;
        if (min > max)
            throw new Error("min must be less than or equal to max");
        let range;
        let result = min;
        if (min < 0.0 && max > 0.0 && max > min + FuzzedDataProvider.max_float) {
            range = max / 2.0 - min / 2.0;
            if (this.consumeBoolean()) {
                result += range;
            }
        }
        else {
            range = max - min;
        }
        return result + range * this.consumeProbabilityFloat();
    }
    /**
     * Consumes a 64-bit `double` from fuzzer input.
     * This is the approach used by libFuzzer to get double numbers from the fuzzer input.
     * @returns a IEEE-754 `double`
     */
    consumeDouble() {
        return this.consumeDoubleInRange(FuzzedDataProvider.min_double, FuzzedDataProvider.max_double);
    }
    /**
     * Consumes at most 9 bytes from fuzzer input and converts them to an
     * IEEE-754 number in the range [min, max].
     * @param min - lower bound of the range (inclusive)
     * @param max - upper bound of the range (inclusive)
     * @returns a `number` in the provided range
     */
    consumeDoubleInRange(min, max) {
        if (min == max)
            return min;
        if (min > max)
            throw new Error("min must be less than or equal to max");
        let range;
        let result = min;
        if (min < 0.0 && max > 0.0 && max > min + FuzzedDataProvider.max_double) {
            range = max / 2.0 - min / 2.0;
            if (this.consumeBoolean()) {
                result += range;
            }
        }
        else {
            range = max - min;
        }
        return result + range * this.consumeProbabilityDouble();
    }
    /**
     * Consumes 4 bytes from the fuzzer input.
     * @returns a number in the range [0.0, 1.0]
     */
    consumeProbabilityFloat() {
        return this.consumeIntegral(4) / 0xffffffff;
    }
    /**
     * Consumes 8 bytes from the fuzzer input and converts them to an IEEE-754`number`
     * in the range [0.0, 1.0].
     * @returns a number in the range [0.0, 1.0]
     */
    consumeProbabilityDouble() {
        const n = this.consumeBigIntegral(8, false);
        const d = (BigInt(0xffffffff) << BigInt(32)) | BigInt(0xffffffff);
        return Number(n) / Number(d);
    }
    /**
     * Picks an element from `array` based on the fuzzer input.
     * Note:The distribution of picks is not perfectly uniform.
     * Note: For array sizes > 48 bits, this function will throw an error.
     * @param array an `array` of type T to pick an element from.
     * @returns an element from `array` chosen based on the fuzzer input
     */
    pickValue(array) {
        if (array.length == 0)
            throw new Error("provided array is empty");
        return array[this.consumeIntegralInRange(0, array.length - 1)];
    }
    /**
     * -----------------------------------------------------
     * Functions for reading data from the front of fuzzer input in
     * big-endian order.
     * -----------------------------------------------------
     */
    /**
     * Consumes an array of booleans from the fuzzer input.
     * The array might be shorter than requested `maxLength` if the fuzzer input
     * is not sufficiently long.
     * @param maxLength - the maximum length of the array
     * @returns an array of booleans
     */
    consumeBooleans(maxLength) {
        if (!Number.isInteger(maxLength)) {
            throw new FloatLengthError();
        }
        const arrayLength = Math.min(this._remainingBytes, maxLength);
        const result = new Array(arrayLength);
        for (let i = 0; i < arrayLength; i++) {
            result[i] = (this.data[this.dataPtr + i] & 1) == 1;
        }
        this._remainingBytes -= arrayLength;
        this.dataPtr += arrayLength;
        return result;
    }
    /**
     * Consumes an array of integrals from fuzzer data.
     * The array might be shorter than requested `maxLength` if the fuzzer input
     * is not sufficiently long.
     * @param maxLength - number of integers to consume
     * @param numBytesPerIntegral - number of bytes to consume for each integral
     * @param isSigned - whether the integrals are signed
     * @returns an array of integrals
     */
    consumeIntegrals(maxLength, numBytesPerIntegral, isSigned = false) {
        if (!Number.isInteger(maxLength) ||
            !Number.isInteger(numBytesPerIntegral)) {
            throw new FloatLengthError();
        }
        const arrayLength = this.computeArrayLength(maxLength, numBytesPerIntegral);
        const result = new Array();
        for (let i = 0; i < arrayLength; i++) {
            result[i] = this.consumeIntegralLEorBE(numBytesPerIntegral, isSigned, false);
        }
        return result;
    }
    /**
     * Consumes an array of big integrals from fuzzer data.
     * The array might be shorter than requested `maxLength` if the fuzzer input
     * is not sufficiently long.
     * @param maxLength - maximum number of integrals to consume
     * @param numBytesPerIntegral - number of bytes to consume for each integral
     * @param isSigned - whether the integrals are signed
     * @returns an array of big integrals
     */
    consumeBigIntegrals(maxLength, numBytesPerIntegral, isSigned = false) {
        if (!Number.isInteger(maxLength) ||
            !Number.isInteger(numBytesPerIntegral)) {
            throw new FloatLengthError();
        }
        const arrayLength = this.computeArrayLength(maxLength, numBytesPerIntegral);
        const result = new Array(arrayLength);
        for (let i = 0; i < arrayLength; i++) {
            result[i] = this.consumeBigIntegralLEorBE(numBytesPerIntegral, isSigned, false);
        }
        return result;
    }
    /**
     * Consumes an array of numbers from the fuzzer input.
     * The array might be shorter than requested `maxLength` if the fuzzer input
     * is not sufficiently long.
     * @param maxLength the maximum length of the array
     * @returns an array of numbers
     */
    consumeNumbers(maxLength) {
        if (!Number.isInteger(maxLength)) {
            throw new FloatLengthError();
        }
        const arrayLength = this.computeArrayLength(maxLength, 8);
        const result = new Array(arrayLength);
        for (let i = 0; i < arrayLength; i++) {
            result[i] = this.consumeNumberBE();
        }
        return result;
    }
    /**
     * Consumes a byte array from fuzzer input.
     * The array might be shorter than requested `maxLength` if the fuzzer input
     * is not sufficiently long.
     * @param maxLength - the maximum length of the output array
     * @returns a byte array of length at most `maxLength`
     */
    consumeBytes(maxLength) {
        if (!Number.isInteger(maxLength)) {
            throw new FloatLengthError();
        }
        const arrayLength = Math.min(this._remainingBytes, maxLength);
        const result = new Array(arrayLength);
        for (let i = 0; i < arrayLength; i++) {
            result[i] = this.data[this.dataPtr + i];
        }
        this._remainingBytes -= arrayLength;
        this.dataPtr += arrayLength;
        return result;
    }
    /**
     * Consumes the remaining fuzzer input as a byte array.
     * Note: After calling this method, further calls to methods of this interface will
     * return fixed values only.
     * @returns a `byte` array
     */
    consumeRemainingAsBytes() {
        return this.consumeBytes(this._remainingBytes);
    }
    /**
     * Consumes a `string` from the fuzzer input.
     * The array might be shorter than requested `maxLength` if the fuzzer input
     * is not sufficiently long.
     * @param maxLength the maximum length of the string
     * @param encoding the encoding of the string
     * @param printable - a boolean, which defaults to false that indicates whether consumed strings
     * should be forced to contain only valid printable characters
     * @returns a `string` of length between 0 and `maxLength` (inclusive)
     */
    consumeString(maxLength, encoding = "ascii", printable = false) {
        if (maxLength < 0)
            throw new Error("maxLength must be non-negative");
        if (!Number.isInteger(maxLength)) {
            throw new FloatLengthError();
        }
        let result;
        const arrayLength = Math.min(maxLength, this._remainingBytes);
        if (printable) {
            result = this.bufToPrintableString(this.data, this.dataPtr, this.dataPtr + arrayLength, encoding);
        }
        else {
            result = this.data.toString(encoding, this.dataPtr, this.dataPtr + arrayLength);
        }
        this.dataPtr += arrayLength;
        this._remainingBytes -= arrayLength;
        return result;
    }
    /**
     * Helper function that converts the given string type into one that only
     * contains printable characters. Elements in `buf` that are already in
     * ASCII printable range are not undergoing any conversion.
     * Known limitations:
     *   numbers [32; 97] will have the probability of about 0.01172 of occuring,
     *   numbers [98; 126] will have probability of 0.00781 of occurring.
     * @param buf - Buffer that contains arbitrary values
     * @param min - lower bound at which processing of the provided `Buffer` shall begin
     * @param max - upper bound, analogous to the lower bound
     * @param encoding - a valid `BufferEncoding`.
     * @returns a string that was sanitized and only contains printable characters
     */
    bufToPrintableString(buf, min, max, encoding) {
        const newBuf = new Uint8Array(max - min);
        for (let i = min; i < max; i++) {
            newBuf[i - min] = this.lookupTable[buf[i]];
        }
        return new TextDecoder(encoding).decode(newBuf);
    }
    /**
     * Consumes the remaining bytes of the fuzzer input as a string.
     * @param encoding - the encoding of the string
     * @param printable - a boolean, which defaults to false that indicates whether consumed strings
     * should be forced to contain only valid printable characters
     * @returns a string constructed from the remaining bytes of the fuzzer input using the given encoding
     */
    consumeRemainingAsString(encoding = "ascii", printable = false) {
        return this.consumeString(this._remainingBytes, encoding, printable);
    }
    /**
     * Consumes an array of `string`s from the fuzzer input.
     * The array and the `string`s might be shorter than requested `maxArrayLength` and `maxStringLength`,
     * if the fuzzer input is not sufficiently long.
     * @param maxArrayLength the maximum length of the array
     * @param maxStringLength the maximum length of the strings
     * @param encoding the encoding of the strings
     * @param printable - a boolean, which defaults to false that indicates whether consumed strings
     * should be forced to contain only valid printable characters
     * @returns an array containing strings constructed from the remaining bytes of the fuzzer input using the given encoding
     */
    consumeStringArray(maxArrayLength, maxStringLength, encoding = "ascii", printable = false) {
        if (!Number.isInteger(maxArrayLength) ||
            !Number.isInteger(maxStringLength)) {
            throw new FloatLengthError();
        }
        const strs = [];
        while (strs.length < maxArrayLength && this.remainingBytes > 0) {
            const str = this.consumeString(maxStringLength, encoding, printable);
            if (str || str === "") {
                strs.push(str);
            }
        }
        return strs;
    }
    /**
     * Picks values from an array based on the fuzzer input.
     * Indices picked by this method do not repeat for the duration of the function call.
     * Note: The distribution of picks is not perfectly uniform.
     * @param array the `array` to pick elements from.
     * @param numValues the number of values to pick.
     * @returns an array of size `numValues` from `array` chosen based on the
     *    fuzzer input
     */
    pickValues(array, numValues) {
        if (array.length == 0)
            throw new Error("array must not be empty");
        if (!Number.isInteger(numValues)) {
            throw new FloatLengthError();
        }
        if (numValues < 0)
            throw new Error("numValues must not be negative");
        if (numValues > array.length)
            throw new Error("numValues must not be greater than the array length");
        const result = new Array(numValues);
        const remainingArray = array.slice();
        for (let i = 0; i < numValues; i++) {
            const index = this.consumeIntegralInRange(0, remainingArray.length - 1);
            result[i] = remainingArray[index];
            remainingArray.splice(index, 1);
        }
        return result;
    }
    /**
     * -----------------------------------------------------
     * Internal helper functions
     * -----------------------------------------------------
     */
    /**
     * Consumes an IEEE 754 floating-point number from the front of fuzzer input.
     * @private
     * @returns a `number`
     */
    consumeNumberBE() {
        if (this._remainingBytes == 0)
            return 0;
        // check that we have enough data
        if (this._remainingBytes < 8) {
            const copiedData = Buffer.alloc(8);
            this.data.copy(copiedData, 0, this.dataPtr, this.dataPtr + this._remainingBytes);
            this._remainingBytes = 0;
            return copiedData.readDoubleBE();
        }
        this._remainingBytes -= 8;
        const result = this.data.readDoubleBE(this.dataPtr);
        this.dataPtr += 8;
        return result;
    }
    /**
     * Consumes an integral from the front of fuzzer input.
     * @param maxNumBytes - maximum number of bytes to consume. Must be between 0 and 6.
     *   For larger numbers, use `consumeBigIntLEorBE`.
     * @param isSigned - whether the integer is signed or not
     * @param isLittleEndian - whether the integer is little endian or not
     * @returns an integral
     */
    consumeIntegralLEorBE(maxNumBytes, isSigned = false, isLittleEndian = true) {
        if (maxNumBytes < 0 || maxNumBytes > 6) {
            throw new Error("maxNumBytes must be between 0 and 6: use the corresponding *BigIntegral function instead");
        }
        const min = isSigned ? -(2 ** (8 * maxNumBytes - 1)) : 0;
        const max = isSigned
            ? 2 ** (8 * maxNumBytes - 1) - 1
            : 2 ** (8 * maxNumBytes) - 1;
        return this.consumeIntegralInRangeLEorBE(min, max, isLittleEndian);
    }
    /**
     * Consumes several bytes from fuzzer data and converts them to a number that is
     * in the range of [min, max]. The number of bytes consumed is determined by
     * the size of the range. If there is no input data left, the returned number
     * will be `min`
     * @param min lower bound of the range (inclusive)
     * @param max upper bound of the range (inclusive)
     * @param isLittleEndian bytes are read in little- or big-endian order. Little-endian
     *   signifies that the bytes are considered parameters and thus read from the back of
     *   the fuzzer data. Big-endian signifies that the bytes are considered data and thus
     *   read from the front of the fuzzer data.
     * @returns a number in the provided range
     */
    consumeIntegralInRangeLEorBE(min, max, isLittleEndian = true) {
        if (min == max)
            return min;
        if (min > max)
            throw new Error("min must be less than or equal to max");
        if (this._remainingBytes == 0)
            return min;
        if (max > Number.MAX_SAFE_INTEGER)
            throw new Error("max is too large: use the corresponding *BigIntegral function instead");
        const range = max - min;
        const numBytesToRepresentRange = Math.ceil(Math.log2(range + 1) / 8);
        const numBytesToConsume = Math.min(this._remainingBytes, numBytesToRepresentRange);
        if (numBytesToConsume > 6) {
            throw new Error("requested range exceeds 2**48-1: use the corresponding *BigIntegral function instead");
        }
        this._remainingBytes -= numBytesToConsume;
        let result;
        if (isLittleEndian) {
            result = this.data.readUIntLE(this.dataPtr + this._remainingBytes, numBytesToConsume);
        }
        else {
            result = this.data.readUIntBE(this.dataPtr, numBytesToConsume);
            this.dataPtr += numBytesToConsume;
        }
        return min + (result % (range + 1));
    }
    /**
     * Consumes an integral from the front of fuzzer input.
     * @param maxNumBytes - maximum number of bytes to consume. Must be between 1 and 6.
     *   For larger numbers, use `consumeBigIntLEorBE`.
     * @param isSigned - whether the integer is signed or not
     * @param isLittleEndian - whether the integer is little endian or not
     * @returns an integral
     */
    consumeBigIntegralLEorBE(maxNumBytes, isSigned = false, isLittleEndian = true) {
        let min, max;
        if (isSigned) {
            min = BigInt(-(2 ** (maxNumBytes * 8 - 1)));
            max = BigInt(2 ** (maxNumBytes * 8 - 1) - 1);
        }
        else {
            min = BigInt(0);
            max = (BigInt(1) << BigInt(maxNumBytes * 8)) - BigInt(1);
        }
        return this.consumeBigIntegralInRangeLEorBE(min, max, isLittleEndian);
    }
    /**
     * Consumes several bytes from fuzzer data and converts them to a bigint that is
     * in the range of [min, max]. The number of bytes consumed is determined by
     * the size of the range. If there is no input data left, the returned number
     * will be `min`
     * @param min lower bound of the range (inclusive)
     * @param max upper bound of the range (inclusive)
     * @param isLittleEndian bytes are read in little- or big-endian order. Little-endian
     *   signifies that the bytes are considered parameters and thus read from the back of
     *   the fuzzer data. Big-endian signifies that the bytes are considered data and thus
     *   read from the front of the fuzzer data.
     * @returns a bigint in the provided range
     */
    consumeBigIntegralInRangeLEorBE(min, max, isLittleEndian = true) {
        if (min == max)
            return min;
        if (min > max)
            throw new Error("min must be less than or equal to max");
        const range = max - min;
        let offset = BigInt(0);
        let result = BigInt(0);
        let nextByte;
        while (range >> offset > BigInt(0) && this._remainingBytes > 0) {
            this._remainingBytes--;
            if (isLittleEndian) {
                nextByte = BigInt(this.data[this.dataPtr + this._remainingBytes]);
            }
            else {
                nextByte = BigInt(this.data[this.dataPtr]);
                this.dataPtr++;
            }
            result = (result << BigInt(8)) | nextByte;
            offset += BigInt(8);
        }
        return (result % (range + BigInt(1))) + min;
    }
    /**
     * Computes how many elements (defined by the number of bytes per element) can be read
     * from the fuzzer input data.
     * @param maxLength - maximum number of elements to read
     * @param numBytesPerElement - number of bytes used by each element
     * @returns number of elements that can be read
     */
    computeArrayLength(maxLength, numBytesPerElement) {
        const numAvailableBytes = Math.min(this._remainingBytes, maxLength * numBytesPerElement);
        return Math.ceil(numAvailableBytes / numBytesPerElement);
    }
}
exports.FuzzedDataProvider = FuzzedDataProvider;
//# sourceMappingURL=FuzzedDataProvider.js.map