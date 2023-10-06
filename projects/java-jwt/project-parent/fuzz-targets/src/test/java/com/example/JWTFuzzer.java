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

package com.example;

import com.code_intelligence.jazzer.api.FuzzedDataProvider;
import com.code_intelligence.jazzer.junit.FuzzTest;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.AlgorithmMismatchException;
import com.auth0.jwt.exceptions.JWTDecodeException;
import com.auth0.jwt.interfaces.DecodedJWT;

class JWTFuzzer {
    @FuzzTest
    void myFuzzTest(FuzzedDataProvider data) {
        String secret = data.consumeString(500);
        Algorithm [] algorithms = {Algorithm.HMAC256(secret), Algorithm.HMAC384(secret), Algorithm.HMAC512(secret)};

        try {
            String token = data.consumeRemainingAsString();
            DecodedJWT decodedJWT = JWT.decode(token);
            DecodedJWT jwt = JWT.require(data.pickValue(algorithms))
                    .build()
                    .verify(decodedJWT);
        } catch (JWTDecodeException | AlgorithmMismatchException | NullPointerException e) {
        }
    }
}