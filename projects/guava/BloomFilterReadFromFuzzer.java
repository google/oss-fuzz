// Copyright 2024 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
////////////////////////////////////////////////////////////////////////////////

import com.code_intelligence.jazzer.api.FuzzedDataProvider;
import com.code_intelligence.jazzer.api.FuzzerSecurityIssueCritical;
import com.google.common.hash.BloomFilter;
import com.google.common.hash.Funnels;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;

public class BloomFilterReadFromFuzzer {

    public static void fuzzerTestOneInput(FuzzedDataProvider data) {

        byte[] input = data.consumeRemainingAsBytes();

        /*
         * BloomFilter serialized format:
         *
         * byte strategyOrdinal
         * byte numHashFunctions
         * int  dataLength
         * long[dataLength] data
         */
        if (input.length < 6) {
            return;
        }

        /*
         * Extract attacker-controlled allocation metadata for reporting only.
         *
         * The real allocation must still occur inside Guava to prove impact.
         */
        int dataLength =
                ((input[2] & 0xFF) << 24)
              | ((input[3] & 0xFF) << 16)
              | ((input[4] & 0xFF) <<  8)
              |  (input[5] & 0xFF);

        long requestedBytes = -1L;
        double amplification = -1.0;

        if (dataLength >= 0) {
            try {
                requestedBytes =
                        Math.multiplyExact((long) dataLength,
                                           (long) Long.BYTES);

                amplification =
                        (double) requestedBytes / (double) input.length;

            } catch (ArithmeticException ignored) {
                /*
                 * Overflow itself is interesting but we still want Guava's
                 * real behavior.
                 */
            }
        }

        try (InputStream is = new ByteArrayInputStream(input)) {

            BloomFilter<String> filter =
                    BloomFilter.readFrom(
                            is,
                            Funnels.stringFunnel(StandardCharsets.UTF_8));

            filter.mightContain("probe");

        } catch (OutOfMemoryError e) {

            StringBuilder message = new StringBuilder();

            message.append(
                "BloomFilter.readFrom() performs attacker-controlled " +
                "heap allocation from serialized metadata without " +
                "application-level bounds checking.\n\n");

            message.append("Input size: ")
                   .append(input.length)
                   .append(" bytes\n");

            message.append("dataLength: ")
                   .append(dataLength)
                   .append("\n");

            if (requestedBytes >= 0) {
                message.append("Requested allocation: ")
                       .append(requestedBytes)
                       .append(" bytes\n");

                message.append("Amplification factor: ")
                       .append(String.format("%.2f", amplification))
                       .append("x\n");
            }

            message.append("\nRoot cause:\n")
                   .append("BloomFilter.readFrom() trusts serialized ")
                   .append("dataLength metadata and propagates it into ")
                   .append("LockFreeBitArray allocation logic without ")
                   .append("validating whether the requested allocation ")
                   .append("size is reasonable for untrusted input.\n\n");

            message.append("Underlying JVM error: ")
                   .append(e.getMessage());

            throw new FuzzerSecurityIssueCritical(message.toString());

        } catch (IOException
                | IllegalArgumentException
                | ArithmeticException e) {

            /*
             * Expected for malformed inputs.
             */
        }
    }
}
