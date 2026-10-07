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

import org.springframework.security.oauth2.core.OAuth2AccessToken;

import java.time.Instant;
import java.util.Arrays;
import java.util.LinkedHashSet;
import java.util.Set;

public class OAuth2AccessTokenFuzzer {

    private static final OAuth2AccessToken.TokenType TOKEN_TYPE = OAuth2AccessToken.TokenType.BEARER;
    private static final Instant ISSUED_AT = Instant.now();
    private static final Instant EXPIRES_AT = Instant.from(ISSUED_AT).plusSeconds(60);

    public static void fuzzerTestOneInput(FuzzedDataProvider data) {

        Set<String> scope;
        String tmpScope;
        String value;
        boolean proceed = true;
        OAuth2AccessToken accessToken = null;

        boolean isScope = data.consumeBoolean();
        if (isScope) {

            tmpScope = data.consumeString(250);
            value = data.consumeString(250);

            scope = new LinkedHashSet<>(Arrays.asList(tmpScope));
            try {
                accessToken = new OAuth2AccessToken(TOKEN_TYPE, value, ISSUED_AT, EXPIRES_AT, scope);
            }
            catch (IllegalArgumentException iae) {
                proceed = false;
             }
        }
        else {
            value = data.consumeRemainingAsString();

            try {
                accessToken = new OAuth2AccessToken(TOKEN_TYPE, value, ISSUED_AT, EXPIRES_AT);
            }
            catch (IllegalArgumentException iae) {
                proceed = false;
             }
        }

        if (proceed) {
            String tokenValue = accessToken.getTokenValue();
            int hashCode = accessToken.hashCode();
            OAuth2AccessToken compareToken = new OAuth2AccessToken(TOKEN_TYPE, value, ISSUED_AT, EXPIRES_AT);
            boolean compareTokens = accessToken.equals(compareToken);
        }
    }

}
