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
///////////////////////////////////////////////////////////////////////////
import com.code_intelligence.jazzer.api.FuzzedDataProvider;
import com.google.api.client.auth.oauth.OAuthSigner;
import com.google.api.client.auth.oauth.OAuthHmacSigner;
import com.google.api.client.auth.oauth.OAuthHmacSha256Signer;
import com.google.api.client.auth.oauth.OAuthRsaSigner;
import java.security.GeneralSecurityException;

// Generated with https://github.com/ossf/fuzz-introspector/tree/main/tools/auto-fuzz
// Minor modifications to beautify code and ensure exception is caught.
// jvm-autofuzz-heuristics-2
// Heuristic name: jvm-autofuzz-heuristics-2
// Target method: [com.google.api.client.auth.oauth.OAuthHmacSha256Signer] public java.lang.String computeSignature(java.lang.String) throws java.security.GeneralSecurityException
// Target method: [com.google.api.client.auth.oauth.OAuthHmacSigner] public java.lang.String computeSignature(java.lang.String) throws java.security.GeneralSecurityException
// Target method: [com.google.api.client.auth.oauth.OAuthRsaSigner] public java.lang.String computeSignature(java.lang.String) throws java.security.GeneralSecurityException
public class OauthSignerFuzzer {
  public static void fuzzerTestOneInput(FuzzedDataProvider data) {
    try {
      OAuthSigner obj = null;
      switch (data.consumeInt(1, 3)) {
        case 1:
          obj = new OAuthHmacSigner();
          break;
        case 2:
          obj = new OAuthHmacSha256Signer(data.consumeString(data.remainingBytes() / 2));
          break;
        case 3:
          obj = new OAuthRsaSigner();
          break;
      }
      obj.computeSignature(data.consumeRemainingAsString());
    } catch (GeneralSecurityException e1) {
      // Known exception
    }
  }
}
