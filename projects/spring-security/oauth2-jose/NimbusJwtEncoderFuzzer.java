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

import org.springframework.security.oauth2.jwt.NimbusJwtEncoder;
import org.springframework.security.oauth2.jwt.JwsHeader;
import org.springframework.security.oauth2.jwt.JwtEncoderParameters;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;
import org.springframework.security.oauth2.jwt.JwtEncodingException;

import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.KeyType;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.util.Base64URL;

import java.time.temporal.ChronoUnit;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Collections;
import java.util.LinkedHashMap;

public class NimbusJwtEncoderFuzzer {


    public static void fuzzerTestOneInput(FuzzedDataProvider data) {

        String keyId = data.consumeString(200);
        String x5t256 = data.consumeString(300);

        List<JWK> jwkList = new ArrayList<>();

        //
        MockJwk mockJwk = new NimbusJwtEncoderFuzzer.MockJwk(KeyType.RSA, keyId, x5t256);
        jwkList.add(mockJwk);

        JWKSource<SecurityContext> jwkSource = (jwkSelector, securityContext) -> jwkSelector.select(new JWKSet(jwkList));
        NimbusJwtEncoder jwtEncoder = new NimbusJwtEncoder(jwkSource);

        JwsHeader jwsHeader = JwsHeader
            .with(SignatureAlgorithm.RS256)
            .build();
        JwtClaimsSet jwtClaimsSet = jwtClaimsSet().build();

        try {
                Jwt encodedJws = jwtEncoder.encode(JwtEncoderParameters.from(jwsHeader, jwtClaimsSet));
        }
        catch(JwtEncodingException jee) {

        }
    }

    public static JwtClaimsSet.Builder jwtClaimsSet() {
        String issuer = "https://provider.com";
        Instant issuedAt = Instant.now();
        Instant expiresAt = issuedAt.plus(1, ChronoUnit.HOURS);

        // @formatter:off
        return JwtClaimsSet.builder()
            .issuer(issuer)
            .subject("subject")
            .audience(Collections.singletonList("client-1"))
            .issuedAt(issuedAt)
            .notBefore(issuedAt)
            .expiresAt(expiresAt)
            .id("jti")
            .claim("custom-claim-name", "custom-claim-value");
    }

    private static final class MockJwk extends JWK{

        protected MockJwk(KeyType kty, String kid, String x5t256) {
            super(kty, null, null, null, kid, null, null, new Base64URL(x5t256), null, null);
            //TODO Auto-generated constructor stub
        }
    
        @Override
        public LinkedHashMap<String, ?> getRequiredParams() {
            // TODO Auto-generated method stub
            return null;
        }
    
        @Override
        public boolean isPrivate() {
            // TODO Auto-generated method stub
            return false;
        }
    
        @Override
        public JWK toPublicJWK() {
            // TODO Auto-generated method stub
            return null;
        }
    
        @Override
        public int size() {
            // TODO Auto-generated method stub
            return 0;
        }
    }
    
}