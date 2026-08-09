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
import com.code_intelligence.jazzer.api.FuzzedDataProvider;

import io.netty.internal.tcnative.Buffer;
import io.netty.internal.tcnative.CertificateVerifier;
import io.netty.internal.tcnative.SSL;
import io.netty.internal.tcnative.SSLContext;

import java.io.File;
import java.nio.ByteBuffer;

public class NettyTcnativeFuzzer {
  private static final int[] protocols = {
    SSL.SSL_PROTOCOL_SSLV2,
    SSL.SSL_PROTOCOL_SSLV3,
    SSL.SSL_PROTOCOL_TLSV1,
    SSL.SSL_PROTOCOL_TLSV1_1,
    SSL.SSL_PROTOCOL_TLSV1_2,
    SSL.SSL_PROTOCOL_ALL
  };

  private static final int[] modes = {
    SSL.SSL_MODE_CLIENT,
    SSL.SSL_MODE_SERVER,
    SSL.SSL_MODE_COMBINED
  };

  static {
    System.load(new File(System.getenv("this_dir") + "/libnetty_tcnative_linux_x86_64.so").getAbsolutePath());
  }

  public static void fuzzerTestOneInput(FuzzedDataProvider data) {
    Integer choice = data.consumeInt();
    Long sslContextId;

    try {
      sslContextId = NettyTcnativeFuzzer.createSSLContext(data);
    } catch (Exception e) {
      return;
    }

    switch (choice % 20) {
      case 0:
        CertificateVerifier.isValid(data.consumeInt());
        break;
      case 1:
        Buffer.address(ByteBuffer.wrap(data.consumeRemainingAsBytes()));
        break;
      case 2:
        Buffer.size(ByteBuffer.wrap(data.consumeRemainingAsBytes()));
        break;
      case 3:
        SSLContext.clearOptions(sslContextId, data.consumeInt());
        break;
      case 4:
        SSLContext.disableOcsp(sslContextId);
        break;
      case 5:
        SSLContext.enableOcsp(sslContextId, data.consumeBoolean());
        break;
      case 6:
        SSLContext.free(sslContextId);
        break;
      case 7:
        SSLContext.getMode(sslContextId);
        break;
      case 8:
        SSLContext.getOptions(sslContextId);
        break;
      case 9:
        SSLContext.getSessionCacheMode(sslContextId);
        break;
      case 10:
        SSLContext.getSessionCacheSize(sslContextId);
        break;
      case 11:
        SSLContext.getSessionCacheTimeout(sslContextId);
        break;
      case 12:
        SSLContext.getSslCtx(sslContextId);
        break;
      case 13:
        SSLContext.sessionAccept(sslContextId);
        break;
      case 14:
        SSLContext.sessionAcceptGood(sslContextId);
        break;
      case 15:
        SSLContext.sessionAcceptRenegotiate(sslContextId);
        break;
      case 16:
        SSLContext.sessionCacheFull(sslContextId);
        break;
      case 17:
        SSLContext.sessionCbHits(sslContextId);
        break;
      case 18:
        SSLContext.sessionConnect(sslContextId);
        break;
      case 19:
        SSLContext.sessionConnectGood(sslContextId);
        break;
    }
  }

  private static Long createSSLContext(FuzzedDataProvider data) throws Exception {
    Integer protocol_choice = data.pickValue(protocols);
    Integer mode_choice = data.pickValue(modes);
    return SSLContext.make(protocol_choice, mode_choice);
  }
}
