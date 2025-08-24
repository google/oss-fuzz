/// <reference types="node" />
/**
 * Error class for functions that accept a length value which is thrown if that length is not a whole number to ensure
 * the fuzzed data buffer is only ever indexed by whole numbers.
 */
export declare class FloatLengthError extends Error {
    constructor();
}
/**
 * Helper class for reading primitive types from the bytes of the raw fuzzer input.
 * Arrays are read from the beginning of the data buffer, whereas individual elements are read
 * from the end of the data buffer.
 * This implementation is based on the FuzzedDataProvider.h from the libFuzzer library
 * https://github.com/llvm-mirror/compiler-rt/blob/master/include/fuzzer/FuzzedDataProvider.h
 */
export declare class FuzzedDataProvider {
    private readonly data;
    private dataPtr;
    /** The number of remaining bytes that can be consumed from the fuzzer input data. */
    _remainingBytes: number;
    /**
     * A lookup table that maps input values to output characters in a cyclical manner.
     * The output characters are evenly distributed across the range of printable ASCII characters (32-126)
     */
    private lookupTable;
    static readonly min_float = -3.4028235e+38;
    static readonly max_float = 3.4028235e+38;
    static readonly min_double: number;
    static readonly max_double: number;
    /**
     * @param data - a buffer containing the fuzzer input
     */
    constructor(data: Buffer);
    /**
     * @returns the number of remaining bytes in the fuzzer input.
     */
    get remainingBytes(): number;
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
    consumeBoolean(): boolean;
    /**
     * Consumes an Integral number from the fuzzer input.
     * @param maxNumBytes - the maximum number of bytes to consume from the fuzzer input data
     * @param isSigned - whether the number is signed
     * @returns an integral
     */
    consumeIntegral(maxNumBytes: number, isSigned?: boolean): number;
    /**
     * Consumes several bytes from fuzzer data and converts them to a number that is
     * in the range of [min, max]. The number of bytes consumed is determined by
     * the size of the range. If there is no more fuzzer data available, the returned
     * number will be `min`.
     * @param min lower bound of the range (inclusive)
     * @param max upper bound of the range (inclusive)
     * @returns a number in the provided range
     */
    consumeIntegralInRange(min: number, max: number): number;
    /**
     * Consumes a big integral from the fuzzer input.
     * @param maxNumBytesToConsume - the maximum number of bytes to consume from the fuzzer input data
     * @param isSigned - whether the number is signed
     * @returns a big integral
     */
    consumeBigIntegral(maxNumBytesToConsume: number, isSigned?: boolean): bigint;
    /**
     * Consumes several bytes from fuzzer data and converts them to a bigint that is
     * in the range of [min, max]. The number of bytes consumed is determined by
     * the size of the range. If there is no more fuzzer data available, the returned
     * number will be `min`.
     * @param min lower bound of the range (inclusive)
     * @param max upper bound of the range (inclusive)
     * @returns a number in the provided range
     */
    consumeBigIntegralInRange(min: bigint, max: bigint): bigint;
    /**
     * Consumes am IEEE 754 floating-point number from the fuzzer input.
     * The number is read as is, without any conversion.
     * @returns a `number` that may have a special value (e.g. a NaN or infinity)
     */
    consumeNumber(): number;
    /**
     * Consumes at most 9 bytes from fuzzer input and converts them to an
     * IEEE-754 number in the range [min, max].
     * @param min - lower bound of the range (inclusive)
     * @param max - upper bound of the range (inclusive)
     * @returns a `number` in the provided range
     */
    consumeNumberInRange(min: number, max: number): number;
    /**
     * Consumes a 32-bit `float` from the fuzzer input.
     * @returns a `float` that may have a special value (e.g. a NaN or infinity)
     */
    consumeFloat(): number;
    /**
     * Consumes a 32-bit `float` from fuzzer input and converts it to an
     * IEEE-754 number in the range [min, max].
     * @param min - lower bound of the range (inclusive)
     * @param max - upper bound of the range (inclusive)
     * @returns a `float` in the provided range
     */
    consumeFloatInRange(min: number, max: number): number;
    /**
     * Consumes a 64-bit `double` from fuzzer input.
     * This is the approach used by libFuzzer to get double numbers from the fuzzer input.
     * @returns a IEEE-754 `double`
     */
    consumeDouble(): number;
    /**
     * Consumes at most 9 bytes from fuzzer input and converts them to an
     * IEEE-754 number in the range [min, max].
     * @param min - lower bound of the range (inclusive)
     * @param max - upper bound of the range (inclusive)
     * @returns a `number` in the provided range
     */
    consumeDoubleInRange(min: number, max: number): number;
    /**
     * Consumes 4 bytes from the fuzzer input.
     * @returns a number in the range [0.0, 1.0]
     */
    consumeProbabilityFloat(): number;
    /**
     * Consumes 8 bytes from the fuzzer input and converts them to an IEEE-754`number`
     * in the range [0.0, 1.0].
     * @returns a number in the range [0.0, 1.0]
     */
    consumeProbabilityDouble(): number;
    /**
     * Picks an element from `array` based on the fuzzer input.
     * Note:The distribution of picks is not perfectly uniform.
     * Note: For array sizes > 48 bits, this function will throw an error.
     * @param array an `array` of type T to pick an element from.
     * @returns an element from `array` chosen based on the fuzzer input
     */
    pickValue<Type>(array: Array<Type>): Type;
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
    consumeBooleans(maxLength: number): boolean[];
    /**
     * Consumes an array of integrals from fuzzer data.
     * The array might be shorter than requested `maxLength` if the fuzzer input
     * is not sufficiently long.
     * @param maxLength - number of integers to consume
     * @param numBytesPerIntegral - number of bytes to consume for each integral
     * @param isSigned - whether the integrals are signed
     * @returns an array of integrals
     */
    consumeIntegrals(maxLength: number, numBytesPerIntegral: number, isSigned?: boolean): number[];
    /**
     * Consumes an array of big integrals from fuzzer data.
     * The array might be shorter than requested `maxLength` if the fuzzer input
     * is not sufficiently long.
     * @param maxLength - maximum number of integrals to consume
     * @param numBytesPerIntegral - number of bytes to consume for each integral
     * @param isSigned - whether the integrals are signed
     * @returns an array of big integrals
     */
    consumeBigIntegrals(maxLength: number, numBytesPerIntegral: number, isSigned?: boolean): bigint[];
    /**
     * Consumes an array of numbers from the fuzzer input.
     * The array might be shorter than requested `maxLength` if the fuzzer input
     * is not sufficiently long.
     * @param maxLength the maximum length of the array
     * @returns an array of numbers
     */
    consumeNumbers(maxLength: number): number[];
    /**
     * Consumes a byte array from fuzzer input.
     * The array might be shorter than requested `maxLength` if the fuzzer input
     * is not sufficiently long.
     * @param maxLength - the maximum length of the output array
     * @returns a byte array of length at most `maxLength`
     */
    consumeBytes(maxLength: number): number[];
    /**
     * Consumes the remaining fuzzer input as a byte array.
     * Note: After calling this method, further calls to methods of this interface will
     * return fixed values only.
     * @returns a `byte` array
     */
    consumeRemainingAsBytes(): number[];
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
    consumeString(maxLength: number, encoding?: BufferEncoding | undefined, printable?: boolean | undefined): string;
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
    private bufToPrintableString;
    /**
     * Consumes the remaining bytes of the fuzzer input as a string.
     * @param encoding - the encoding of the string
     * @param printable - a boolean, which defaults to false that indicates whether consumed strings
     * should be forced to contain only valid printable characters
     * @returns a string constructed from the remaining bytes of the fuzzer input using the given encoding
     */
    consumeRemainingAsString(encoding?: BufferEncoding | undefined, printable?: boolean | undefined): string;
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
    consumeStringArray(maxArrayLength: number, maxStringLength: number, encoding?: BufferEncoding | undefined, printable?: boolean | undefined): string[];
    /**
     * Picks values from an array based on the fuzzer input.
     * Indices picked by this method do not repeat for the duration of the function call.
     * Note: The distribution of picks is not perfectly uniform.
     * @param array the `array` to pick elements from.
     * @param numValues the number of values to pick.
     * @returns an array of size `numValues` from `array` chosen based on the
     *    fuzzer input
     */
    pickValues<Type>(array: Array<Type>, numValues: number): Array<Type>;
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
    private consumeNumberBE;
    /**
     * Consumes an integral from the front of fuzzer input.
     * @param maxNumBytes - maximum number of bytes to consume. Must be between 0 and 6.
     *   For larger numbers, use `consumeBigIntLEorBE`.
     * @param isSigned - whether the integer is signed or not
     * @param isLittleEndian - whether the integer is little endian or not
     * @returns an integral
     */
    private consumeIntegralLEorBE;
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
    private consumeIntegralInRangeLEorBE;
    /**
     * Consumes an integral from the front of fuzzer input.
     * @param maxNumBytes - maximum number of bytes to consume. Must be between 1 and 6.
     *   For larger numbers, use `consumeBigIntLEorBE`.
     * @param isSigned - whether the integer is signed or not
     * @param isLittleEndian - whether the integer is little endian or not
     * @returns an integral
     */
    private consumeBigIntegralLEorBE;
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
    private consumeBigIntegralInRangeLEorBE;
    /**
     * Computes how many elements (defined by the number of bytes per element) can be read
     * from the fuzzer input data.
     * @param maxLength - maximum number of elements to read
     * @param numBytesPerElement - number of bytes used by each element
     * @returns number of elements that can be read
     */
    private computeArrayLength;
}
