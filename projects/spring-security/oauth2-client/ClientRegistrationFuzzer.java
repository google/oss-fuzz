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

import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistration.ProviderDetails;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.AuthenticationMethod;
import org.springframework.security.oauth2.core.AuthorizationGrantType;

import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.stream.Stream;
import java.util.Map;
import java.util.Set;

public class ClientRegistrationFuzzer {

     public static void fuzzerTestOneInput(FuzzedDataProvider data) {

        
        String registration = "registration-1";
        String scope = "email";
        String clientName = "Client 1";
        String clientId = "client-1";
        String clientSecret = "secret";
        String uri = "https://example.com";
        String config = "config-1";
        String value = "value-1";

        int switchInput = data.consumeInt(0,7);
        switch(switchInput) {
            case 0 : 
                registration = data.consumeRemainingAsString();
                break;
            case 1 :
                scope = data.consumeRemainingAsString();
                break;
            case 2 :
                clientName = data.consumeRemainingAsString();
                break;
            case 3 :
                clientId = data.consumeRemainingAsString();
                break;
            case 4 :
                clientSecret = data.consumeRemainingAsString();
                break;
            case 5 :
                uri = data.consumeRemainingAsString();
                break;
            case 6 :
                config = data.consumeRemainingAsString();
                break;
            case 7 :
                value = data.consumeRemainingAsString();
                break;
        }

        Map<String, Object> configurationMetadata = new LinkedHashMap<>();
            configurationMetadata.put(config, value);
        Map<String, Object> PROVIDER_CONFIGURATION_METADATA = Collections
            .unmodifiableMap(configurationMetadata);

        ClientRegistration clientRegistration = null;
        try {
            clientRegistration = ClientRegistration.withRegistrationId(registration)
                .clientId(clientId)
                .clientSecret(clientSecret)
                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .redirectUri(uri)
                .scope(scope)
                .authorizationUri(uri)
                .tokenUri(uri)
                .userInfoAuthenticationMethod(AuthenticationMethod.HEADER)
                .issuerUri(uri)
                .providerConfigurationMetadata(null)
                .jwkSetUri(uri)
                .clientName(clientName)
                .build();

            ProviderDetails pd = clientRegistration.getProviderDetails();
        }
        catch (IllegalArgumentException iae){}

    }

}
