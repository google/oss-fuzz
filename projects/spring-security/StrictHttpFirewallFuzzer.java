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
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.http.HttpMethod;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.security.web.firewall.StrictHttpFirewall;
import org.springframework.security.web.firewall.RequestRejectedException;
import com.code_intelligence.jazzer.api.FuzzerSecurityIssueMedium;
import java.util.function.Predicate;
import java.util.Enumeration;
import java.util.regex.Pattern;
import java.util.regex.Matcher;
import java.util.ArrayList;
import java.util.List;
import jakarta.servlet.http.HttpServletRequest;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.lang.IllegalStateException;

public class StrictHttpFirewallFuzzer {
    record Header(String n, String v) {};

    public static void fuzzerTestOneInput(FuzzedDataProvider data) throws Exception {
        StrictHttpFirewall firewall = new StrictHttpFirewall();
	    MockHttpServletRequest request = new MockHttpServletRequest("GET", "");

        boolean invalidMethod = data.consumeBoolean();

        if (invalidMethod) {
            request.setMethod(data.consumeString(50));
        }

        List<Header> maliciousHeaders = new ArrayList<Header>();
        List<String> maliciousParameterNames = new ArrayList<String>();
        List<String> maliciousUrls = new ArrayList<String>();

        // Feed fuzzer data into the request
        for (int i = 0; i < data.consumeInt(1, 5); i++) {
            String url = data.consumeString(400);
            switch (data.consumeInt(0, 5)) {
                case 0:
                    request.setPathInfo(url);
                    maliciousUrls.add(url);
                    break;
                case 1:
                    request.setContextPath(url);
                    maliciousUrls.add(url);
                    break;
                case 2:
                    request.setRequestURI(url);
                    maliciousUrls.add(url);
                    break;
                case 3:
                    request.setServletPath(url);
                    maliciousUrls.add(url);
                    break;
                case 4:
                    String parameterName = data.consumeString(100);
                    if (parameterName.isEmpty()) {
                        break;
                    }
                    request.addParameter(parameterName, "Dummy value");
                    maliciousParameterNames.add(parameterName);
                    break;
                case 5:
                    Header header = new Header(data.consumeString(100), data.consumeString(100));
                    if (header.v().isEmpty() || header.n().isEmpty()) {
                        break;
                    }
                    request.addHeader(header.n(), header.v());
                    maliciousHeaders.add(header);
            }
        }

        HttpServletRequest servletRequest;
        try {
            servletRequest = firewall.getFirewalledRequest(request);

            // getHeader() and getParameter() should throw a rejection exception if it contains invalid chars
            for (Header header : maliciousHeaders) {
                servletRequest.getHeader(header.n());
            }

            for (String parameterName : maliciousParameterNames) {
                servletRequest.getParameter(parameterName);
            }

        } catch (RequestRejectedException | IllegalStateException e) {
            return;
        }

        for (String forbiddenChar : firewall.getEncodedUrlBlocklist()) {
            if (request.getPathInfo() != null && request.getPathInfo().contains(forbiddenChar)
                || request.getRequestURI() != null && request.getRequestURI().contains(forbiddenChar)
                || request.getContextPath() != null && request.getContextPath().contains(forbiddenChar)
                || request.getServletPath() != null && request.getServletPath().contains(forbiddenChar)) {
                throw new FuzzerSecurityIssueMedium("Malicious char not filtered: " + forbiddenChar);
            }
        }

        for (Header header : maliciousHeaders) {
            validate(header.n());
            String v = servletRequest.getHeader(header.n());
            validate(v);
        }

        for (String name : maliciousParameterNames) {
            validate(name);
        }
    }

    // Check for invalid chars
    // https://docs.spring.io/spring-security/site/docs/current/api/org/springframework/security/web/firewall/StrictHttpFirewall.html#setAllowedHeaderNames(java.util.function.Predicate)
    private static void validate(String value) {
        for (char c : value.toCharArray()) {
            if (Character.isISOControl(c) || !Character.isDefined(c)) {
                throw new FuzzerSecurityIssueMedium("Malicious char not filtered: \\x" + String.format("%04x", (int) c) + " in `" + value + "`");
            }
        }
    }
} 
