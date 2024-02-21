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

import com.google.auth.oauth2.*;
import com.google.auth.http.HttpTransportFactory;
import com.google.api.client.http.HttpTransport;
import com.google.api.client.testing.http.MockHttpTransport;

import java.io.ByteArrayInputStream;
import java.io.IOException;


class CredentialsFuzzer {
    @FuzzTest
    void myFuzzTest(FuzzedDataProvider data) {
        boolean b = data.consumeBoolean();
        MockHttpTransportFactory transportFactory = new MockHttpTransportFactory();
        ByteArrayInputStream bais = new ByteArrayInputStream(data.consumeRemainingAsBytes());
        
        try {
            GoogleCredentials [] credentials = {
                    b ? GoogleCredentials.fromStream(bais) : GoogleCredentials.fromStream(bais, transportFactory), 
                    b ? ServiceAccountCredentials.fromStream(bais) : ServiceAccountCredentials.fromStream(bais, transportFactory),
                    b ? ExternalAccountCredentials.fromStream(bais) : ExternalAccountCredentials.fromStream(bais, transportFactory),
                    b ? ExternalAccountAuthorizedUserCredentials.fromStream(bais) : ExternalAccountAuthorizedUserCredentials.fromStream(bais, transportFactory),
                    b ? UserCredentials.fromStream(bais) : UserCredentials.fromStream(bais, transportFactory)
                    };
            
            GoogleCredentials googleCredentials = data.pickValue(credentials);
            googleCredentials.refreshIfExpired();
            googleCredentials.refreshAccessToken();
            googleCredentials.getAccessToken();
        } catch (IOException expected) {
        } catch (IllegalArgumentException | NullPointerException | ClassCastException | IllegalStateException ignored) {
            // Need to catch in order to find more interesting bugs.
        }
    }

    static class MockHttpTransportFactory implements HttpTransportFactory {
        MockHttpTransport transport = new MockHttpTransport();

        @Override
        public HttpTransport create() {
            return transport;
        }
    }
}